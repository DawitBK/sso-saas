-- P1-4: TOTP replay protection.
--
-- verifyTotp() accepts a +/-1 step drift window and kept no record of which
-- counter had already been used, so an observed 6-digit code stayed valid for up
-- to 90 seconds and could be submitted more than once. Anyone who shoulder-surfs,
-- keylogs, or intercepts a single code gets a second bite at it.
--
-- totp_last_counter stores the highest time-step counter already accepted for the
-- account; verification now refuses any counter at or below it. NULL means "never
-- verified" (freshly enrolled, or enrolled before this migration) and accepts any
-- counter once, which is correct — there is no earlier use to replay.
ALTER TABLE idp_users
  ADD COLUMN IF NOT EXISTS totp_last_counter BIGINT;

-- P1-17: the account-lockout gate is now two-dimensional (per-email, per-IP, and
-- per (email, IP) pair) so a single remote actor cannot lock any employee out of
-- every system on the platform just by knowing their address. That turns one
-- indexed-by-nothing COUNT(*) into a filtered aggregate over both columns, on a
-- table that is on the login critical path and only grows.
CREATE INDEX IF NOT EXISTS idp_login_events_email_created_idx
  ON idp_login_events (email, created_at DESC);

CREATE INDEX IF NOT EXISTS idp_login_events_ip_created_idx
  ON idp_login_events (ip, created_at DESC)
  WHERE success = FALSE;
