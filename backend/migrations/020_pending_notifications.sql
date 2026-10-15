-- Durable retry for "tell the other system this person is signed out".
--
-- Disabling someone (or signing them out everywhere) ends every SSO credential at once, but DMS and GMS hold their own sessions and are
-- told over HTTP. If DMS or GMS is down at that moment the call used to be tried a few times in a row and then forgotten: the account
-- was dark in SSO and still live in DMS or GMS until its token expired, with only a warning to the administrator to fix it by hand.
-- This table keeps each notification that did not get through, and a background job retries it with a growing delay for up to 48 hours.
--
-- One pending row per (kind, account) at a time: signing the same person out five times while DMS is down queues one retry, not five.

CREATE TABLE IF NOT EXISTS idp_pending_notifications (
  id              BIGSERIAL PRIMARY KEY,
  kind            TEXT        NOT NULL CHECK (kind IN ('dms-logout', 'gms-revoke')),
  account_id      TEXT        NOT NULL,
  email           TEXT        NOT NULL DEFAULT '',
  status          TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done', 'abandoned')),
  attempts        INTEGER     NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- The failure's class only, never a message that could name a host, database or role.
  last_error      TEXT        NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  finished_at     TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idp_pending_notifications_one_pending
  ON idp_pending_notifications (kind, account_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idp_pending_notifications_due
  ON idp_pending_notifications (next_attempt_at) WHERE status = 'pending';
