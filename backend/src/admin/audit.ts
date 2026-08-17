/**
 * Admin-console audit trail (idp_admin_audit): every mutation records who did
 * what to whom. Writes are awaited inside the mutation handlers so a change
 * without its audit row can't silently succeed.
 *
 * Tamper-evident hash chain (security audit finding #20): every row also
 * carries `sequence_number` (from a Postgres sequence), `previous_hash` (the
 * prior row's `entry_hash`), and `entry_hash` = HMAC-SHA256 over a canonical
 * string of the row's own fields + `previous_hash`. This mirrors DMS's
 * src/modules/audit/audit.service.ts (writeAuditLog / verifyAuditChain) —
 * same idea, simplified to ONE global chain (no per-tenant partitioning:
 * IdP is single-tenant) and one global advisory lock key.
 *
 * Atomicity note: unlike DMS (which reuses an ambient request transaction via
 * shared/transaction.ts's runInTransaction so writeAuditLog commits atomically
 * with the domain change it accompanies), IdP has no request-transaction-reuse
 * mechanism at all — every mutation in src/admin/router.ts already runs as its
 * own separate pool.query() call with no wrapping transaction (see e.g.
 * applyAccess()'s own comment on the same gap for its cross-DB writes). This
 * function therefore opens its OWN dedicated transaction, scoped only to the
 * audit write itself: that makes the hash chain internally consistent under
 * concurrent writers, but the audit row is still not atomically tied to the
 * domain mutation it describes (a crash between the two could in principle
 * leave one without the other). Closing that gap fully would mean building
 * IdP's own version of DMS's request-transaction infrastructure, which is out
 * of scope here — flagged the same way DMS's own audit originally flagged it
 * before DMS fixed it.
 */

import crypto from 'node:crypto';
import type { Request } from 'express';
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';

/** Lock/sequence key for the single global admin-audit chain. */
const CHAIN_KEY = 'idp_admin_audit';

/** Prefix tagging pre-migration rows backfilled by migrations/007_phase_e.sql
 *  with a non-HMAC content fingerprint instead of a real chain hash — see
 *  that migration's comment for why. verifyAuditChain() below recognizes it. */
const LEGACY_PREFIX = 'legacy-sha256:';

/** Recursively sort object keys so JSON.stringify is stable across a Postgres
 *  JSONB round-trip (JSONB does not preserve original key order/whitespace).
 *  Applied identically at write time and at verify time so the HMAC input
 *  matches regardless of how Postgres reformats the stored `detail` value. */
function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value));
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

/** Canonical string hashed (via HMAC-SHA256) into entry_hash — every field
 *  that identifies the row, plus previous_hash, so altering ANY of them (or
 *  reordering the chain) is detectable. */
function chainData(fields: {
  sequenceNumber: string;
  createdAtIso: string;
  action: string;
  actorEmail: string;
  target: string;
  detail: unknown;
  ip: string;
  userAgent: string;
  previousHash: string | null;
}): string {
  return (
    fields.sequenceNumber +
    fields.createdAtIso +
    fields.action +
    fields.actorEmail +
    fields.target +
    canonicalJson(fields.detail) +
    fields.ip +
    fields.userAgent +
    (fields.previousHash ?? '')
  );
}

export async function writeAudit(
  req: Request,
  actorEmail: string,
  action: string,
  target: string,
  detail: Record<string, unknown> = {},
): Promise<void> {
  const ip = req.ip ?? '';
  const userAgent = String(req.get('user-agent') ?? '').slice(0, 300);
  const createdAt = new Date();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serializes writers on the single global chain so it can't fork under
    // concurrency (mirrors DMS's per-tenant pg_advisory_xact_lock, collapsed
    // to one lock key since IdP has no tenants). Released automatically at
    // COMMIT/ROLLBACK.
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [CHAIN_KEY]);

    const { rows: lastRows } = await client.query<{ entry_hash: string }>(
      'SELECT entry_hash FROM idp_admin_audit ORDER BY sequence_number DESC LIMIT 1',
    );
    const previousHash = lastRows[0]?.entry_hash ?? null;

    const { rows: seqRows } = await client.query<{ sequence_number: string }>(
      `SELECT nextval(pg_get_serial_sequence('idp_admin_audit', 'sequence_number')) AS sequence_number`,
    );
    const sequenceNumber = seqRows[0].sequence_number;

    const entryHash = crypto
      .createHmac('sha256', IDP_CONFIG.auditHmacSecret)
      .update(
        chainData({
          sequenceNumber,
          createdAtIso: createdAt.toISOString(),
          action,
          actorEmail,
          target,
          detail,
          ip,
          userAgent,
          previousHash,
        }),
      )
      .digest('hex');

    await client.query(
      `INSERT INTO idp_admin_audit
         (actor_email, action, target, detail, ip, user_agent, sequence_number, previous_hash, entry_hash, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [actorEmail, action, target, JSON.stringify(detail), ip, userAgent, sequenceNumber, previousHash, entryHash, createdAt],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export interface AuditRow {
  id: string;
  actor_email: string;
  action: string;
  target: string;
  detail: Record<string, unknown>;
  ip: string;
  user_agent: string;
  sequence_number: string;
  created_at: string;
}

export async function recentAudit(limit = 100): Promise<AuditRow[]> {
  const { rows } = await pool.query<AuditRow>(
    `SELECT id, actor_email, action, target, detail, ip, user_agent, sequence_number, created_at
     FROM idp_admin_audit ORDER BY sequence_number DESC LIMIT $1`,
    [limit],
  );
  return rows;
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  legacyCount: number;
  brokenAtSequence?: string;
  message: string;
}

/**
 * Walks every idp_admin_audit row in sequence order and confirms: (1) each
 * non-legacy row's stored entry_hash matches a freshly recomputed HMAC, and
 * (2) each row's previous_hash correctly points at the prior row's
 * entry_hash. Legacy rows (see migrations/007_phase_e.sql) are excluded from
 * (1) — there is no secret to verify them against — but still checked for (2)
 * so the chain as a whole stays contiguous and gap-free.
 */
export async function verifyAuditChain(): Promise<ChainVerification> {
  const { rows } = await pool.query<{
    sequence_number: string;
    previous_hash: string | null;
    entry_hash: string;
    actor_email: string;
    action: string;
    target: string;
    detail: unknown;
    ip: string;
    user_agent: string;
    created_at: string;
  }>(
    `SELECT sequence_number, previous_hash, entry_hash, actor_email, action, target, detail, ip, user_agent, created_at
     FROM idp_admin_audit ORDER BY sequence_number ASC`,
  );

  if (rows.length === 0) {
    return { valid: true, checked: 0, legacyCount: 0, message: 'No audit entries to verify.' };
  }

  let expectedPrevious: string | null = null;
  let legacyCount = 0;

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];

    if (i > 0 && r.previous_hash !== expectedPrevious) {
      return {
        valid: false,
        checked: i,
        legacyCount,
        brokenAtSequence: r.sequence_number,
        message: `Chain linkage broken at sequence ${r.sequence_number}: previous_hash does not match the prior row's entry_hash.`,
      };
    }

    if (r.entry_hash.startsWith(LEGACY_PREFIX)) {
      legacyCount++;
    } else {
      const expectedHash = crypto
        .createHmac('sha256', IDP_CONFIG.auditHmacSecret)
        .update(
          chainData({
            sequenceNumber: r.sequence_number,
            createdAtIso: new Date(r.created_at).toISOString(),
            action: r.action,
            actorEmail: r.actor_email,
            target: r.target,
            detail: r.detail,
            ip: r.ip,
            userAgent: r.user_agent,
            previousHash: r.previous_hash,
          }),
        )
        .digest('hex');

      if (expectedHash !== r.entry_hash) {
        return {
          valid: false,
          checked: i,
          legacyCount,
          brokenAtSequence: r.sequence_number,
          message: `Chain broken at sequence ${r.sequence_number}: stored entry_hash does not match the recomputed HMAC.`,
        };
      }
    }

    expectedPrevious = r.entry_hash;
  }

  return {
    valid: true,
    checked: rows.length,
    legacyCount,
    message: `Verified ${rows.length} audit entries (${legacyCount} legacy, unverifiable pre-chain row(s) excluded from HMAC recomputation).`,
  };
}
