-- Rolls back 024: the e-mail rule goes back to what 023 said (local@domain, no dot required); the route and the console still require the dot.
ALTER TABLE idp_users DROP CONSTRAINT IF EXISTS idp_users_email_valid;
ALTER TABLE idp_users ADD CONSTRAINT idp_users_email_valid
  CHECK (char_length(email) <= 254 AND email ~ '^[^[:space:]@]+@[^[:space:]@]+$') NOT VALID;
