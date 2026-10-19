-- Platform licensing (docs/operations/PLATFORM-LICENSING.md): one licence per system (SSO, GMS, DMS), issued here and checked by each system.
--
-- ADDITIVE ONLY: two new tables, no seed rows, no change to any existing table. "No row" for a system means state `unconfigured`: nothing is
-- enforced and every system behaves exactly as before, so applying this migration to a server that has no licence yet changes nothing for its users.
-- A row appears only when the platform administrator saves one in Admin > Licences; "revoke" deletes the row again and keeps the event.

CREATE TABLE IF NOT EXISTS licenses (
  system      TEXT        PRIMARY KEY CHECK (system IN ('sso', 'gms', 'dms')),
  customer    TEXT        NOT NULL DEFAULT '' CHECK (char_length(customer) <= 200),
  -- NULL = perpetual (never expires).
  expires_at  TIMESTAMPTZ,
  grace_days  INTEGER     NOT NULL DEFAULT 14 CHECK (grace_days BETWEEN 0 AND 365),
  warn_days   INTEGER     NOT NULL DEFAULT 30 CHECK (warn_days  BETWEEN 0 AND 365),
  -- NULL = unlimited seats.
  max_users   INTEGER     CHECK (max_users IS NULL OR max_users >= 1),
  -- Enabled GATEABLE module keys (licenses/catalog.ts). NULL = every module enabled.
  modules     TEXT[],
  notes       TEXT        NOT NULL DEFAULT '' CHECK (char_length(notes) <= 2000),
  -- Bumped on every change and never reused for a system, even across a revoke and a new licence (consumers ignore a token with a lower version).
  version     INTEGER     NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- The administrator's email, or the literal 'platform' for the platform administrator (who must stay anonymous, see auth/platform-admin.ts).
  updated_by  TEXT        NOT NULL DEFAULT ''
);

-- Append-only history: every create, update, extend and revoke, with the record before and after. The service only ever INSERTs here, and the
-- same change is also written to the tamper-evident admin audit chain (idp_admin_audit).
CREATE TABLE IF NOT EXISTS license_events (
  id          BIGSERIAL   PRIMARY KEY,
  system      TEXT        NOT NULL CHECK (system IN ('sso', 'gms', 'dms')),
  action      TEXT        NOT NULL CHECK (action IN ('create', 'update', 'extend', 'revoke')),
  actor       TEXT        NOT NULL DEFAULT '',
  -- The licence version this event produced (a revoke also takes the next number, which is what keeps versions monotonic).
  version     INTEGER     NOT NULL DEFAULT 1,
  before      JSONB,
  after       JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS license_events_system_time ON license_events (system, created_at DESC, id DESC);
