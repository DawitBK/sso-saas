-- P2-6: three defects in the tamper-evident admin-audit chain.
--
-- 1. NO FIELD DELIMITER. chainData() concatenated
--    sequenceNumber + createdAtIso + action + actorEmail + target +
--    canonicalJson(detail) + ip + userAgent + previousHash
--    with nothing between the fields, so two different field splits produce the
--    same HMAC input: action="user.disa"/target="ble:bob@x" hashes identically to
--    action="user.disable"/target="bob@x". A canonicalization defect in the one
--    function whose entire job is being canonical — an attacker with write access
--    could shift a boundary and keep the chain verifying.
--
--    Fixed by hashing a JSON ARRAY of the fields (hash_version = 2), which is
--    unambiguous. That changes every hash, so it is VERSIONED: existing rows stay
--    version 1 and are verified with the old algorithm. Historical rows are NOT
--    rewritten — rewriting an audit trail to fix its hashing is itself tampering,
--    and it would destroy the only evidence that the old rows were untouched.
--
-- 2. FRONT-TRUNCATION WAS UNDETECTABLE. verifyAuditChain skipped the linkage
--    check for i === 0 and asserted nothing about the first row, so deleting rows
--    1..N left a chain that verified perfectly clean. The anchor table below
--    records the chain head (highest sequence number + its entry_hash) in the SAME
--    transaction as each write; verification compares both ENDS of the chain
--    against it, which is what makes truncation from either end visible.
--
-- 3. UNBOUNDED MEMORY. verifyAuditChain SELECTed the whole table and materialized
--    it, from a synchronous admin GET. Now batched (see verifyAuditChain).

ALTER TABLE idp_admin_audit
  ADD COLUMN IF NOT EXISTS hash_version SMALLINT NOT NULL DEFAULT 1;

-- New rows are written as version 2 by the application. The default of 1 is
-- correct for every row that already exists and must not be changed.

/*
 * Single-row anchor. `id` is fixed so there can only ever be one row.
 *
 * Updated inside writeAudit's transaction, under the same advisory lock, so the
 * anchor and the chain can never disagree: either both the row and the anchor
 * land, or neither does.
 */
CREATE TABLE IF NOT EXISTS idp_admin_audit_anchor (
  id              SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  sequence_number BIGINT      NOT NULL,
  entry_hash      TEXT        NOT NULL,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

/*
 * Seed the anchor from the current chain head, if there is one. Bootstrapping it
 * from existing data cannot prove the existing chain was never truncated — that
 * evidence does not exist and pretending otherwise would be worse than saying so.
 * From this point forward truncation IS detectable.
 */
INSERT INTO idp_admin_audit_anchor (id, sequence_number, entry_hash)
SELECT 1, sequence_number, entry_hash
  FROM idp_admin_audit
 ORDER BY sequence_number DESC
 LIMIT 1
ON CONFLICT (id) DO NOTHING;
