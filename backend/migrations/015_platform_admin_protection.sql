-- Platform administrator protection, SSO database layer (brief item 5.14).
--
-- The platform administrator is the platform owner's account. In SSO it is
-- invisible to the IdP admin console (users, groups, sessions, sign-ins, audit,
-- keys all leave it out) and cannot be disabled, deleted, renamed, signed out,
-- re-grouped or locked out by anyone, including every IdP administrator. The
-- application enforces that (src/auth/platform-admin.ts); this migration repeats
-- the hard parts in the database so they hold for a person at a SQL prompt too.
--
--  1. idp_users.is_platform_admin marks the account. It can only be set or
--     cleared with the vault open.
--  2. A vault, identical in design to the DMS one (DMS migration
--     20261004000002): a password the owner chooses with scripts/platform-vault.ts,
--     stored only as a bcrypt hash, never in any file or env var and unknown to
--     the application. platform_vault_unlock(password) opens ONE session for a few
--     minutes. Failures are counted in a sequence (not undone by ROLLBACK), and
--     ten in a row locks the vault until the owner resets it as superuser.
--  3. Guard triggers: without the vault open, the account cannot be deleted,
--     deactivated, renamed or un-flagged, and nothing can add it to, or remove it
--     from, a group. A failed-login or failed-MFA lockout is silently ignored for
--     it, so guessing its password can never lock it out.
--
-- WHAT THIS CANNOT DO: SSO connects as the PostgreSQL superuser, and a superuser
-- can always drop a trigger. So the real protection against someone holding the
-- superuser password is that the account's identity is not stored in the clear
-- (the seed script stores a keyed pseudonym instead of the email when
-- PLATFORM_ADMIN_PEPPER is set). See /PLATFORM-ADMIN-AUTONOMY.md.
--
-- SAFE: adds one column with a default, one table set, functions and triggers.
-- Nothing existing is dropped, renamed or backfilled; the DROP statements only
-- remove this migration's own earlier objects so it can be re-run.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS is_platform_admin BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idp_users_platform_admin_idx ON idp_users (id) WHERE is_platform_admin;

CREATE TABLE IF NOT EXISTS platform_vault (
  id          smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  secret_hash text NOT NULL,
  set_at      timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS platform_vault_unlocked (
  pid           integer     NOT NULL,
  backend_start timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  PRIMARY KEY (pid, backend_start)
);
CREATE TABLE IF NOT EXISTS platform_vault_log (
  id      bigserial PRIMARY KEY,
  at      timestamptz NOT NULL DEFAULT now(),
  event   text NOT NULL,
  db_user text NOT NULL DEFAULT session_user
);
CREATE SEQUENCE IF NOT EXISTS platform_vault_failures MINVALUE 1 START 1;

REVOKE ALL ON platform_vault, platform_vault_unlocked, platform_vault_log FROM PUBLIC;
REVOKE ALL ON SEQUENCE platform_vault_failures FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform_vault_failure_count() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM platform_vault_failures;
$$;

CREATE OR REPLACE FUNCTION platform_vault_is_unlocked() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (
    SELECT 1 FROM platform_vault_unlocked u
     WHERE u.pid = pg_backend_pid()
       AND u.backend_start = (SELECT a.backend_start FROM pg_stat_activity a WHERE a.pid = pg_backend_pid())
       AND u.expires_at > now()
  );
$$;

CREATE OR REPLACE FUNCTION platform_vault_unlock(p_password text, p_minutes integer DEFAULT 10)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  v_hash  text;
  v_ok    boolean;
  v_fails bigint;
BEGIN
  v_fails := platform_vault_failure_count();
  IF v_fails >= 10 THEN
    RAISE EXCEPTION 'platform vault is locked after repeated failures; the owner must reset it' USING ERRCODE = '42501';
  END IF;
  SELECT secret_hash INTO v_hash FROM platform_vault WHERE id = 1;
  IF v_hash IS NULL THEN
    RAISE EXCEPTION 'platform vault has no password set' USING ERRCODE = '42501';
  END IF;
  v_ok := (crypt(coalesce(p_password, ''), v_hash) = v_hash);
  IF NOT v_ok THEN
    PERFORM nextval('platform_vault_failures');
    INSERT INTO platform_vault_log (event) VALUES ('unlock_failed');
    RETURN false;
  END IF;
  PERFORM setval('platform_vault_failures', 1, false);
  DELETE FROM platform_vault_unlocked WHERE expires_at <= now();
  INSERT INTO platform_vault_unlocked (pid, backend_start, expires_at)
  VALUES (
    pg_backend_pid(),
    (SELECT a.backend_start FROM pg_stat_activity a WHERE a.pid = pg_backend_pid()),
    now() + make_interval(mins => least(greatest(coalesce(p_minutes, 10), 1), 60))
  )
  ON CONFLICT (pid, backend_start) DO UPDATE SET expires_at = EXCLUDED.expires_at;
  INSERT INTO platform_vault_log (event) VALUES ('unlock_ok');
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION platform_vault_lock() RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  DELETE FROM platform_vault_unlocked WHERE pid = pg_backend_pid();
$$;

REVOKE ALL ON FUNCTION platform_vault_failure_count() FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_vault_is_unlocked() FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_vault_unlock(text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_vault_lock() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_vault_unlock(text, integer) TO PUBLIC;
GRANT EXECUTE ON FUNCTION platform_vault_lock() TO PUBLIC;
GRANT EXECUTE ON FUNCTION platform_vault_is_unlocked() TO PUBLIC;

-- ---------------------------------------------------------------- triggers ---

CREATE OR REPLACE FUNCTION idp_platform_admin_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  v_pa boolean;
BEGIN
  IF platform_vault_is_unlocked() THEN
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;

  IF TG_TABLE_NAME = 'idp_users' THEN
    IF TG_OP = 'INSERT' THEN
      IF NEW.is_platform_admin THEN
        RAISE EXCEPTION 'a platform administrator account can only be created through the vault' USING ERRCODE = '42501';
      END IF;
      RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
      IF OLD.is_platform_admin THEN
        RAISE EXCEPTION 'the platform administrator account cannot be deleted' USING ERRCODE = '42501';
      END IF;
      RETURN OLD;
    ELSE
      IF NEW.is_platform_admin IS DISTINCT FROM OLD.is_platform_admin THEN
        RAISE EXCEPTION 'the platform administrator flag can only be changed through the vault' USING ERRCODE = '42501';
      END IF;
      IF OLD.is_platform_admin THEN
        IF NEW.is_active IS DISTINCT FROM TRUE OR NEW.email IS DISTINCT FROM OLD.email THEN
          RAISE EXCEPTION 'the platform administrator account cannot be disabled or renamed' USING ERRCODE = '42501';
        END IF;
        -- guessing its password or MFA code must never lock it out
        NEW.locked_until := NULL;
        NEW.failed_logins := 0;
        NEW.mfa_locked_until := NULL;
        NEW.mfa_failed_attempts := 0;
      END IF;
      RETURN NEW;
    END IF;
  ELSE
    -- idp_user_groups: nobody adds the account to, or removes it from, a group
    SELECT is_platform_admin INTO v_pa FROM idp_users
     WHERE id = CASE WHEN TG_OP = 'DELETE' THEN OLD.user_id ELSE NEW.user_id END;
    IF coalesce(v_pa, false) THEN
      RAISE EXCEPTION 'the platform administrator account cannot be re-grouped' USING ERRCODE = '42501';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
  END IF;
END $$;

DROP TRIGGER IF EXISTS idp_platform_admin_guard_users ON idp_users;
CREATE TRIGGER idp_platform_admin_guard_users
  BEFORE INSERT OR UPDATE OR DELETE ON idp_users
  FOR EACH ROW EXECUTE FUNCTION idp_platform_admin_guard();

DROP TRIGGER IF EXISTS idp_platform_admin_guard_groups ON idp_user_groups;
CREATE TRIGGER idp_platform_admin_guard_groups
  BEFORE INSERT OR UPDATE OR DELETE ON idp_user_groups
  FOR EACH ROW EXECUTE FUNCTION idp_platform_admin_guard();
