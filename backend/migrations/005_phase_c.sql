-- Phase C: MFA/TOTP + sign-in event log.

ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Every sign-in attempt at the IdP (success and failure) — drives the admin
-- Sign-ins page and the brute-force anomaly alerts.
CREATE TABLE IF NOT EXISTS idp_login_events (
  id         BIGSERIAL   PRIMARY KEY,
  email      TEXT        NOT NULL,
  success    BOOLEAN     NOT NULL,
  reason     TEXT        NOT NULL DEFAULT '',   -- '' on success | bad_password | locked | inactive | mfa_failed
  ip         TEXT        NOT NULL DEFAULT '',
  user_agent TEXT        NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idp_login_events_created_idx ON idp_login_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idp_login_events_email_idx ON idp_login_events (email, created_at DESC);
