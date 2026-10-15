-- The table now requires a dot in the e-mail domain, like the create-user form and route already do (migration 023 left it out on purpose, see below).
--
-- 023 accepted `local@domain` with no dot so that an account already imported without one would not break the migration.
--
-- SAFE on existing data, as in 023: the rule is added NOT VALID (enforced for every new and changed row at once), then validated; if an old row still breaks it the constraint
-- stays NOT VALID with a notice instead of failing the migration, and keeps refusing every new dotless address. Correct or remove such rows, then validate the constraint.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idp_users_email_valid') THEN
    ALTER TABLE idp_users DROP CONSTRAINT idp_users_email_valid;
  END IF;
  ALTER TABLE idp_users ADD CONSTRAINT idp_users_email_valid
    CHECK (char_length(email) <= 254 AND email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$') NOT VALID;
END $$;

DO $$
BEGIN
  ALTER TABLE idp_users VALIDATE CONSTRAINT idp_users_email_valid;
EXCEPTION WHEN check_violation THEN
  RAISE NOTICE 'constraint idp_users_email_valid left NOT VALID: an existing row has a domain with no dot (new and changed rows are still checked)';
END $$;
