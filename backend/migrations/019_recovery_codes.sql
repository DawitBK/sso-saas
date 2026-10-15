-- Two-factor recovery codes.
--
-- Until now a person who lost their phone could not sign in until an administrator reset their two-factor. A set of single-use
-- recovery codes, shown once when two-factor is switched on, lets them get back in themselves and then enrol a new device.
--
-- Only a keyed hash of each code is stored (HMAC-SHA256 keyed from TOTP_ENCRYPTION_KEY), never the code, so a copy of this table
-- reveals nothing usable. A code is single use: used_at is set atomically by the statement that accepts it. Turning two-factor off,
-- or an administrator resetting it, deletes the person's codes (ON DELETE CASCADE covers account removal).

CREATE TABLE IF NOT EXISTS idp_recovery_codes (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID NOT NULL REFERENCES idp_users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  used_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idp_recovery_codes_hash_idx ON idp_recovery_codes (user_id, code_hash);
CREATE INDEX IF NOT EXISTS idp_recovery_codes_user_idx ON idp_recovery_codes (user_id) WHERE used_at IS NULL;
