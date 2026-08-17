-- Phase E: tamper-evident hash chain + IP/user-agent capture for idp_admin_audit.
--
-- Security audit finding #20 (UNKNOWN-UNKNOWNS-IDP.md): idp_admin_audit was an
-- ordinary, fully mutable table — no append-only constraint, no hash chain —
-- so "who has admin, since when" couldn't be trusted to survive someone with
-- DB access editing rows directly. It also never recorded the acting admin's
-- IP/user-agent, unlike idp_login_events (migrations/005_phase_c.sql), which
-- already captures both on every sign-in attempt (see
-- src/interactions/router.ts's recordLoginEvent()).
--
-- This adds:
--   - ip / user_agent: same capture idp_login_events already does.
--   - sequence_number: this row's position in the global admin-audit chain.
--     ONE global chain (not per-tenant) — IdP is single-tenant, unlike DMS's
--     audit.service.ts which partitions by tenant.
--   - previous_hash / entry_hash: HMAC-SHA256 tamper-evident chain, written by
--     the updated writeAudit() (src/admin/audit.ts) under a Postgres advisory
--     lock so concurrent writers can't fork the chain. Mirrors the design in
--     DMS's src/modules/audit/audit.service.ts (writeAuditLog /
--     verifyAuditChain), simplified to a single global chain/lock instead of
--     per-tenant.
--
-- Backfill for pre-existing rows: these predate the chain and were never
-- protected by it — there is NO way to retroactively prove they weren't
-- altered before this migration ran, and pretending otherwise would be worse
-- than admitting it. We still give every legacy row a sequence_number (by id
-- / insertion order, the only ordering we have) and a chained SHA-256 content
-- fingerprint — NOT an HMAC, since the HMAC secret doesn't exist retroactively
-- for these rows and hardcoding it into a tracked SQL migration file would be
-- a worse leak than doing nothing. Each fingerprint is tagged with a
-- 'legacy-sha256:' prefix; verifyAuditChain() (src/admin/audit.ts) recognizes
-- the prefix and skips HMAC recomputation for those rows — it verifies only
-- their sequence ordering and hash linkage, and never reports them as
-- cryptographically tamper-evident. Real tamper-evidence begins at the first
-- row written by the new writeAudit() after this migration ships, whose
-- previous_hash correctly points at the last legacy row's fingerprint (or is
-- NULL if the table was empty).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE idp_admin_audit ADD COLUMN IF NOT EXISTS ip TEXT NOT NULL DEFAULT '';
ALTER TABLE idp_admin_audit ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';
ALTER TABLE idp_admin_audit ADD COLUMN IF NOT EXISTS sequence_number BIGINT;
ALTER TABLE idp_admin_audit ADD COLUMN IF NOT EXISTS previous_hash TEXT;
ALTER TABLE idp_admin_audit ADD COLUMN IF NOT EXISTS entry_hash TEXT;

-- Assign sequence_number in id (insertion) order to any row that doesn't have
-- one yet. Guarded by WHERE so this whole file stays safe to eyeball/replay.
WITH ordered AS (
  SELECT id, ROW_NUMBER() OVER (ORDER BY id) AS rn
  FROM idp_admin_audit
  WHERE sequence_number IS NULL
)
UPDATE idp_admin_audit a
SET sequence_number = o.rn
FROM ordered o
WHERE a.id = o.id;

-- Chain legacy rows to each other (see comment above). Sequential by nature —
-- each row's fingerprint folds in the previous row's — so this runs as a
-- PL/pgSQL loop rather than a single set-based UPDATE. Audit tables are small
-- and this runs exactly once per pre-existing row, ever.
DO $$
DECLARE
  rec RECORD;
  prev_hash TEXT := NULL;
  computed_hash TEXT;
BEGIN
  FOR rec IN
    SELECT id, actor_email, action, target, detail, ip, user_agent, created_at, sequence_number
    FROM idp_admin_audit
    WHERE entry_hash IS NULL
    ORDER BY sequence_number
  LOOP
    computed_hash := 'legacy-sha256:' || encode(
      digest(
        rec.sequence_number::text || rec.created_at::text || rec.action || rec.actor_email ||
        rec.target || rec.detail::text || rec.ip || rec.user_agent || COALESCE(prev_hash, ''),
        'sha256'
      ),
      'hex'
    );
    UPDATE idp_admin_audit
    SET entry_hash = computed_hash, previous_hash = prev_hash
    WHERE id = rec.id;
    prev_hash := computed_hash;
  END LOOP;
END $$;

-- From here on sequence_number is served by a real sequence so writeAudit()
-- can nextval() it directly under the advisory lock, mirroring DMS's use of
-- pg_get_serial_sequence(...) in audit.service.ts.
CREATE SEQUENCE IF NOT EXISTS idp_admin_audit_seq;
SELECT setval(
  'idp_admin_audit_seq',
  GREATEST((SELECT COALESCE(MAX(sequence_number), 0) FROM idp_admin_audit), 1),
  (SELECT COUNT(*) > 0 FROM idp_admin_audit)
);
ALTER TABLE idp_admin_audit ALTER COLUMN sequence_number SET DEFAULT nextval('idp_admin_audit_seq');
ALTER SEQUENCE idp_admin_audit_seq OWNED BY idp_admin_audit.sequence_number;

ALTER TABLE idp_admin_audit ALTER COLUMN sequence_number SET NOT NULL;
ALTER TABLE idp_admin_audit ALTER COLUMN entry_hash SET NOT NULL;

-- Postgres has no ADD CONSTRAINT IF NOT EXISTS; guard explicitly so this file
-- stays safe to run against a DB that already has the constraint (the migration
-- runner itself tracks applied files and won't replay this normally, but a
-- fresh environment re-running the raw file shouldn't fail here either).
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'idp_admin_audit_sequence_unique'
  ) THEN
    ALTER TABLE idp_admin_audit ADD CONSTRAINT idp_admin_audit_sequence_unique UNIQUE (sequence_number);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idp_admin_audit_sequence_idx ON idp_admin_audit (sequence_number);
