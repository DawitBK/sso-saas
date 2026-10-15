-- The database half of the user-identity rules.
--
-- The console refuses an email that is not an address, an email or name that is too long, and an unknown account source (admin/user-input.ts). Until now nothing
-- underneath said the same, so a script, a seed or a future code path could store what the console would refuse, and a value that slipped past a validator surfaced
-- as an unexplained failure. These CHECKs make the three layers (the form, the route, the table) say one thing; tests/user-input.test.ts fails if the numbers drift.
--
--   email   at most 254 characters (RFC 5321), no whitespace, and local@domain with exactly one @. Postgres regular expressions treat \s inside a bracket expression
--           differently from JavaScript, hence [:space:].
--   names   first and last name at most 100 characters each.
--   source  'local' or 'ad', the only two there are.
--
-- ONE DELIBERATE DIFFERENCE. The create-user route also requires a dot in the domain (person@examplecorp.com); the table does not, because one real, active account
-- imported from GMS has a misspelt address with no dot (see scripts/verify-imported-users.ts, where it is listed as a known typo to be corrected at the source). A
-- CHECK is evaluated on every UPDATE of a row, so a stricter table rule would stop that person signing in (the sign-in updates last_login_at). When the owner has the
-- right address for that account, correct it and tighten this rule in a follow-up migration.
--
-- SAFE on existing data: each constraint is added NOT VALID (enforced for every new and changed row at once, without scanning), then validated; if an old row
-- breaks one, that constraint stays NOT VALID with a notice instead of failing the migration. Checked on the development and mirror databases: every row satisfies all three.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idp_users_email_valid') THEN
    ALTER TABLE idp_users ADD CONSTRAINT idp_users_email_valid
      CHECK (char_length(email) <= 254 AND email ~ '^[^[:space:]@]+@[^[:space:]@]+$') NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idp_users_name_length') THEN
    ALTER TABLE idp_users ADD CONSTRAINT idp_users_name_length
      CHECK (char_length(given_name) <= 100 AND char_length(family_name) <= 100) NOT VALID;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'idp_users_source_known') THEN
    ALTER TABLE idp_users ADD CONSTRAINT idp_users_source_known
      CHECK (source IN ('local', 'ad')) NOT VALID;
  END IF;
END $$;

DO $$
DECLARE
  name TEXT;
BEGIN
  FOREACH name IN ARRAY ARRAY['idp_users_email_valid', 'idp_users_name_length', 'idp_users_source_known'] LOOP
    BEGIN
      EXECUTE format('ALTER TABLE idp_users VALIDATE CONSTRAINT %I', name);
    EXCEPTION WHEN check_violation THEN
      RAISE NOTICE 'constraint % left NOT VALID: existing rows break it (new and changed rows are still checked)', name;
    END;
  END LOOP;
END $$;
