-- Rolls back 018. The columns only carry display information; dropping them loses the rotation date and the "changed by" label.
ALTER TABLE idp_clients DROP COLUMN IF EXISTS secret_rotated_at;
ALTER TABLE idp_clients DROP COLUMN IF EXISTS updated_by;
