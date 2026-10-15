-- Client management from the console (admin > Clients).
--
-- secret_rotated_at: when the console last rotated the client's secret (NULL = never rotated from the console; the age shown is then
--   "since it was created"). Lets the page say "secret is 14 months old" and flag a client still on a development secret.
-- updated_by: the administrator's email, or 'platform' for the platform administrator (who must stay anonymous), or a script name.
--
-- Nothing else changes: client rows, secrets and addresses are untouched.

ALTER TABLE idp_clients ADD COLUMN IF NOT EXISTS secret_rotated_at TIMESTAMPTZ;
ALTER TABLE idp_clients ADD COLUMN IF NOT EXISTS updated_by TEXT NOT NULL DEFAULT '';
