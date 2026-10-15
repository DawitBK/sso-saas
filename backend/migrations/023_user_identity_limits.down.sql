-- Rolls back 023: the console and routes still enforce the same rules, the table just stops repeating them.
ALTER TABLE idp_users DROP CONSTRAINT IF EXISTS idp_users_email_valid;
ALTER TABLE idp_users DROP CONSTRAINT IF EXISTS idp_users_name_length;
ALTER TABLE idp_users DROP CONSTRAINT IF EXISTS idp_users_source_known;
