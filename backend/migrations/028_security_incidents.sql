-- Tamper detection and incident response (docs/sso/SSO-OPERATIONS.md, "Tamper detection and incident response").
--
-- ADDITIVE ONLY: two new tables and one trigger function. Nothing existing is changed.
--
-- security_incidents: one row for every security event SSO's incident response recorded (a refused owner-only operation, a privilege change by someone who is not
-- the owner, a broken audit chain, ...), with what the automatic response did. APPEND-ONLY twice over: triggers refuse UPDATE, DELETE and TRUNCATE, and every
-- row carries previous_hash and entry_hash (HMAC-SHA256 over the row and the previous hash, keyed with the audit secret), so a row removed or edited by
-- someone who can switch the triggers off is still found by verification (ops/incidents.ts verifyIncidentChain). No secret is ever stored in a row.
--
-- security_state: tiny key/value store for detector bookkeeping (the last admin-group membership snapshot, the audit position already inspected). Not evidence;
-- the incident rows are.
CREATE TABLE IF NOT EXISTS security_incidents (
  id              BIGSERIAL   PRIMARY KEY,
  sequence_number BIGINT      NOT NULL UNIQUE,
  occurred_at     TIMESTAMPTZ NOT NULL,
  recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  kind            TEXT        NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 100),
  severity        TEXT        NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
  actor           JSONB       NOT NULL DEFAULT '{}'::jsonb,
  operation       TEXT        NOT NULL DEFAULT '' CHECK (char_length(operation) <= 200),
  detail          JSONB       NOT NULL DEFAULT '{}'::jsonb,
  -- What the automatic response did: { mode, decision, locked, lockWritten, revoked, ... }. Facts, not secrets.
  response        JSONB       NOT NULL DEFAULT '{}'::jsonb,
  previous_hash   TEXT,
  entry_hash      TEXT        NOT NULL,
  hash_version    INTEGER     NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS security_incidents_recent ON security_incidents (sequence_number DESC);

CREATE OR REPLACE FUNCTION security_incidents_refuse_change() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'security_incidents is append-only' USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS security_incidents_no_update ON security_incidents;
CREATE TRIGGER security_incidents_no_update BEFORE UPDATE OR DELETE ON security_incidents
  FOR EACH ROW EXECUTE FUNCTION security_incidents_refuse_change();

DROP TRIGGER IF EXISTS security_incidents_no_truncate ON security_incidents;
CREATE TRIGGER security_incidents_no_truncate BEFORE TRUNCATE ON security_incidents
  FOR EACH STATEMENT EXECUTE FUNCTION security_incidents_refuse_change();

CREATE TABLE IF NOT EXISTS security_state (
  key        TEXT        PRIMARY KEY CHECK (char_length(key) BETWEEN 1 AND 100),
  value      JSONB       NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
