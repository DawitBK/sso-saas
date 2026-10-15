-- Acknowledging a known break in the admin audit chain.
--
-- verifyAuditChain() reports every place the chain no longer holds. Some of those are historical and explained (a restore from an older backup, a
-- one-off repair made by hand years ago) and cannot be fixed without rewriting the very history the chain protects. Until now such a break showed
-- "CHAIN BROKEN" for ever, which trains people to ignore the alarm that is meant to catch the next one.
--
-- An acknowledgement records that a platform administrator looked at ONE specific break and says why it is harmless. It never edits or hides the
-- break: the verifier still lists it, marked acknowledged. It is pinned to the row as it is today (its stored hashes AND a fingerprint of its content),
-- so a row changed again after it was acknowledged is a new, unexplained break. The acknowledgement is itself an entry in the chain.
--
-- Only breaks that exist right now can be acknowledged (the API checks), so nothing can be pre-acknowledged.

CREATE TABLE IF NOT EXISTS idp_audit_chain_acknowledgements (
  sequence_number BIGINT      NOT NULL,
  kind            TEXT        NOT NULL CHECK (kind IN ('hash', 'linkage', 'ordering', 'head')),
  entry_hash      TEXT        NOT NULL,
  previous_hash   TEXT,
  row_fingerprint TEXT        NOT NULL,
  reason          TEXT        NOT NULL CHECK (char_length(reason) >= 20),
  -- 'platform' for the platform administrator (the platform administrator is never named, see auth/platform-admin.ts).
  acknowledged_by TEXT        NOT NULL,
  acknowledged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (sequence_number, kind)
);
