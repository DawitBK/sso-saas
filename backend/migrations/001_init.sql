-- Example Corp IdP — initial schema (edams_idp database).
-- Idempotent: safe to re-run.

-- ─── oidc-provider persistence ──────────────────────────────────────────────
-- Single-table adapter storing every oidc-provider model (Grant, Session,
-- AuthorizationCode, AccessToken, RefreshToken, Interaction, ClientCredentials,
-- DeviceCode, etc.). `kind` = model name; `payload` = the serialized artifact.
CREATE TABLE IF NOT EXISTS oidc_artifacts (
  id          TEXT        NOT NULL,
  kind        TEXT        NOT NULL,
  payload     JSONB       NOT NULL,
  grant_id    TEXT,
  user_code   TEXT,
  uid         TEXT,
  expires_at  TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS oidc_artifacts_grant_idx ON oidc_artifacts (grant_id);
CREATE INDEX IF NOT EXISTS oidc_artifacts_user_code_idx ON oidc_artifacts (user_code);
CREATE INDEX IF NOT EXISTS oidc_artifacts_uid_idx ON oidc_artifacts (uid);
CREATE INDEX IF NOT EXISTS oidc_artifacts_expires_idx ON oidc_artifacts (expires_at) WHERE expires_at IS NOT NULL;

-- ─── JWKS signing keys (persisted, RS256, kid rotation) ─────────────────────
CREATE TABLE IF NOT EXISTS idp_signing_keys (
  kid         TEXT        PRIMARY KEY,
  jwk         JSONB       NOT NULL,          -- private JWK (kept server-side)
  is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  retired_at  TIMESTAMPTZ
);

-- ─── Registered relying parties (OIDC clients) ──────────────────────────────
CREATE TABLE IF NOT EXISTS idp_clients (
  client_id                 TEXT        PRIMARY KEY,
  client_secret             TEXT        NOT NULL,
  redirect_uris             TEXT[]      NOT NULL DEFAULT '{}',
  post_logout_redirect_uris TEXT[]      NOT NULL DEFAULT '{}',
  grant_types               TEXT[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
  name                      TEXT        NOT NULL,
  is_active                 BOOLEAN     NOT NULL DEFAULT TRUE,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Local user store (fallback for non-AD accounts) ────────────────────────
-- AD-primary: most users authenticate via LDAP and are NOT stored here.
-- Local users (service accounts, contractors) are stored with a scrypt hash.
CREATE TABLE IF NOT EXISTS idp_users (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  email          TEXT        NOT NULL UNIQUE,
  email_verified BOOLEAN     NOT NULL DEFAULT FALSE,
  given_name     TEXT        NOT NULL DEFAULT '',
  family_name    TEXT        NOT NULL DEFAULT '',
  password_hash  TEXT,                        -- scrypt: salt:hash (null = cannot local-login)
  source         TEXT        NOT NULL DEFAULT 'local',  -- 'local' | 'ad'
  is_active      BOOLEAN     NOT NULL DEFAULT TRUE,
  failed_logins  INT         NOT NULL DEFAULT 0,
  locked_until   TIMESTAMPTZ,
  last_login_at  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Group memberships for local users, expressed as AD-style group DNs so the
-- issued token carries the same `ad_groups` claim shape whether the user came
-- from AD or the local store.
CREATE TABLE IF NOT EXISTS idp_user_groups (
  user_id   UUID NOT NULL REFERENCES idp_users(id) ON DELETE CASCADE,
  group_dn  TEXT NOT NULL,
  PRIMARY KEY (user_id, group_dn)
);

-- ─── Per-relying-party entitlement (which apps a user/group may open) ───────
-- Drives the SSO portal's app launcher.
CREATE TABLE IF NOT EXISTS idp_app_entitlements (
  relying_party TEXT NOT NULL,   -- client_id, e.g. 'edams' | 'gms' | 'retail-os'
  group_dn      TEXT NOT NULL,   -- AD/local group DN that grants access to that app
  PRIMARY KEY (relying_party, group_dn)
);
