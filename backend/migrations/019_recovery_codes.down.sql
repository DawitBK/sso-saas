-- Rolls back 019. People who relied on a recovery code must ask an administrator to reset their two-factor instead.
DROP TABLE IF EXISTS idp_recovery_codes;
