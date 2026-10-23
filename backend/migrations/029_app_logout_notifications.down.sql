DELETE FROM idp_pending_notifications WHERE kind LIKE 'app-logout:%';
ALTER TABLE idp_pending_notifications DROP CONSTRAINT IF EXISTS idp_pending_notifications_kind_check;
ALTER TABLE idp_pending_notifications
  ADD CONSTRAINT idp_pending_notifications_kind_check
  CHECK (kind IN ('dms-logout', 'gms-revoke'));
