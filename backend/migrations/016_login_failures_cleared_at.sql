-- A password reset (or a successful sign-in) must wipe the slate for the failed-attempt window.
--
-- The IdP counts recent failures from idp_login_events (auth/account.ts evaluateLockout), a table an
-- admin reset never touched. So after "reset password" the row counters were cleared but the event
-- window still held the old failures: for up to 15 minutes the CORRECT new password was refused as
-- 'locked', and the sign-in page shows the same generic message for every failure.
-- idp_users.login_failures_cleared_at records "ignore failures older than this" per account.
ALTER TABLE idp_users ADD COLUMN IF NOT EXISTS login_failures_cleared_at TIMESTAMPTZ;
