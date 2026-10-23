-- Sign-out notifications for the applications that sign in through this IdP besides DMS and GMS (MOS, the product apps).
--
-- A failed notification to one of them is queued like the DMS one (020_pending_notifications.sql), under the kind 'app-logout:<client id>'
-- so that one pending row exists per (application, account) and the retry job knows whom to tell.

ALTER TABLE idp_pending_notifications DROP CONSTRAINT IF EXISTS idp_pending_notifications_kind_check;
ALTER TABLE idp_pending_notifications
  ADD CONSTRAINT idp_pending_notifications_kind_check
  CHECK (kind IN ('dms-logout', 'gms-revoke') OR kind LIKE 'app-logout:%');
