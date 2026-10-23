-- Owner verification (Phase 4 of the platform hardening programme): a per-operation, server-side check that the person using the platform
-- administrator's session really is the owner, so a stolen session alone cannot do an owner-only operation (signing keys, licences,
-- platform settings, application sign-in settings, who is an IdP administrator, audit acknowledgements).
--
-- ADDITIVE ONLY: new tables, no seed rows, no change to any existing table. Until the owner has enrolled (a terminal tool on the server),
-- the tables are empty: in development nothing is enforced (OWNER_VERIFICATION_REQUIRED=false); in production and the mirror the owner-only
-- operations are REFUSED with OWNER_NOT_ENROLLED rather than allowed.
--
-- What is stored, and what is deliberately not:
--   * owner_verification_store.sealed is ONE AES-256-GCM sealed document (key read from a file named by OWNER_STORE_KEY_FILE, kept outside the
--     repository and outside this database). Inside it: the security-question prompts with their salted slow hashes, the owner's mailbox
--     address, the authenticator secret and the keyed hashes of the offline recovery codes. A read of this database alone discloses none of
--     them, and a WRITE to this database cannot forge a different set (the seal is authenticated), only destroy it.
--   * No answer, code, address, secret or ticket is ever written in clear to any table below. Challenges hold a keyed hash of the emailed code.
--   * Counters and one-time-use records (failures, lockout, last authenticator step, used recovery codes, tickets) are plain rows: losing or
--     resetting them could only help someone who already holds a captured code, never someone who holds nothing.

CREATE TABLE IF NOT EXISTS owner_verification_store (
  id             SMALLINT    PRIMARY KEY CHECK (id = 1),
  sealed         TEXT        NOT NULL,
  -- Identifies WHICH key file sealed it (a hash prefix), so a wrong or replaced key file is reported as exactly that.
  key_id         TEXT        NOT NULL,
  -- Optimistic lock for the few in-place updates (a recovery code being used).
  store_version  INTEGER     NOT NULL DEFAULT 1 CHECK (store_version >= 1),
  enrolled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per recovery code already used (the code's id inside the sealed store, never the code). Re-enrolment clears it with the new codes.
CREATE TABLE IF NOT EXISTS owner_recovery_codes_used (
  code_id  TEXT        PRIMARY KEY,
  used_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Failure counters, escalating lockout and the authenticator replay guard (single owner, single row).
CREATE TABLE IF NOT EXISTS owner_verification_state (
  id                    SMALLINT    PRIMARY KEY CHECK (id = 1),
  consecutive_failures  INTEGER     NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
  lockout_level         INTEGER     NOT NULL DEFAULT 0 CHECK (lockout_level >= 0),
  locked_until          TIMESTAMPTZ,
  last_failure_at       TIMESTAMPTZ,
  -- Highest authenticator time step already accepted: a code at or below it is a replay.
  totp_last_step        BIGINT      NOT NULL DEFAULT 0,
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per run of the sequence. Bound to the portal session that started it (a hash, never the cookie) and to ONE operation.
CREATE TABLE IF NOT EXISTS owner_verification_challenges (
  id                    UUID        PRIMARY KEY,
  session_hash          TEXT        NOT NULL,
  account_id            TEXT        NOT NULL,
  operation_key         TEXT        NOT NULL,
  target_hash           TEXT,
  questions_ok_at       TIMESTAMPTZ,
  -- Which factor satisfied the second step: the emailed code, or an offline recovery code when email is unavailable.
  second_kind           TEXT        CHECK (second_kind IN ('email', 'recovery')),
  second_ok_at          TIMESTAMPTZ,
  totp_ok_at            TIMESTAMPTZ,
  finished_at           TIMESTAMPTZ,
  -- Keyed hash of the emailed code (never the code), its expiry, wrong-guess counter and send bookkeeping.
  email_code_hash       TEXT,
  email_code_expires_at TIMESTAMPTZ,
  email_attempts        INTEGER     NOT NULL DEFAULT 0,
  email_sends           INTEGER     NOT NULL DEFAULT 0,
  last_email_sent_at    TIMESTAMPTZ,
  email_failed          BOOLEAN     NOT NULL DEFAULT FALSE,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at            TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS owner_verification_challenges_session ON owner_verification_challenges (session_hash);
CREATE INDEX IF NOT EXISTS owner_verification_challenges_created ON owner_verification_challenges (created_at);

-- Authorisation tickets: issued -> reserved (a request is using it) -> consumed (single use). A request refused for a reason that changed nothing
-- (a 4xx) puts it back to issued until it expires, so a typo does not cost the whole sequence; one that succeeded or failed on the server does not.
CREATE TABLE IF NOT EXISTS owner_verification_tickets (
  jti            UUID        PRIMARY KEY,
  session_hash   TEXT        NOT NULL,
  operation_key  TEXT        NOT NULL,
  target_hash    TEXT,
  audience       TEXT        NOT NULL CHECK (audience IN ('sso', 'dms')),
  state          TEXT        NOT NULL DEFAULT 'issued' CHECK (state IN ('issued', 'reserved', 'consumed')),
  issued_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at     TIMESTAMPTZ NOT NULL,
  reserved_at    TIMESTAMPTZ,
  consumed_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS owner_verification_tickets_expires ON owner_verification_tickets (expires_at);

-- The secret-free record of every step and decision. `detail` holds short facts only (a reason code, an attempt count), never an answer, code,
-- address, secret or ticket. `session_prefix` is the first characters of the session hash, enough to tell sessions apart and nothing more.
CREATE TABLE IF NOT EXISTS owner_verification_audit (
  id              BIGSERIAL   PRIMARY KEY,
  at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event           TEXT        NOT NULL,
  outcome         TEXT        NOT NULL,
  operation_key   TEXT,
  session_prefix  TEXT,
  detail          JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS owner_verification_audit_time ON owner_verification_audit (at DESC, id DESC);
