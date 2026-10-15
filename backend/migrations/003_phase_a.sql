-- Phase A: durability & consistency.

-- Durable web-session store: portal sessions, gateway handoff/relay sessions,
-- and pending OIDC flows. Previously in-memory Maps that died on every restart
-- (logging everyone out of the portal/admin and breaking mid-flight logins).
CREATE TABLE IF NOT EXISTS idp_web_sessions (
  kind       TEXT        NOT NULL,   -- 'portal' | 'gateway' | 'pending_portal' | 'pending_gms'
  key        TEXT        NOT NULL,
  payload    JSONB       NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS idp_web_sessions_expires_idx ON idp_web_sessions (expires_at);

-- Admin-console audit trail: who granted what to whom, when.
CREATE TABLE IF NOT EXISTS idp_admin_audit (
  id          BIGSERIAL   PRIMARY KEY,
  actor_email TEXT        NOT NULL,
  action      TEXT        NOT NULL,   -- e.g. 'user.create' | 'user.access' | 'group.entitlements'
  target      TEXT        NOT NULL DEFAULT '',
  detail      JSONB       NOT NULL DEFAULT '{}'::jsonb,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idp_admin_audit_created_idx ON idp_admin_audit (created_at DESC);
