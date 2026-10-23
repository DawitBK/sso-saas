/**
 * The owner-verification record: every step and decision, WITHOUT secrets (migration 027, owner_verification_audit). Never pass an answer, a code, an
 * address, a secret or a ticket here: `detail` takes short facts only (a reason code, an attempt count). Writing it never fails the request that
 * caused it (a failure is logged), and it is separate from the tamper-evident admin audit chain, which also receives the outcomes that matter
 * (a ticket issued, an operation authorised, a lock).
 */
import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';

export type AuditDetail = Record<string, string | number | boolean | null>;

export async function ownerAudit(
  event: string,
  outcome: 'ok' | 'denied' | 'failed' | 'locked' | 'info',
  opts: { operation?: string; sessionHash?: string; detail?: AuditDetail } = {},
): Promise<void> {
  try {
    await pool.query('INSERT INTO owner_verification_audit (event, outcome, operation_key, session_prefix, detail) VALUES ($1, $2, $3, $4, $5)', [
      event,
      outcome,
      opts.operation ?? null,
      opts.sessionHash ? opts.sessionHash.slice(0, 8) : null,
      JSON.stringify(opts.detail ?? {}),
    ]);
  } catch (err) {
    logger.error({ err, event }, '[idp:owner] could not write an owner verification audit row');
  }
}

export async function recentOwnerAudit(limit = 50): Promise<Array<{ id: string; at: string; event: string; outcome: string; operation: string | null; detail: AuditDetail }>> {
  const { rows } = await pool.query(
    'SELECT id, at, event, outcome, operation_key AS operation, detail FROM owner_verification_audit ORDER BY id DESC LIMIT $1',
    [Math.max(1, Math.min(limit, 500))],
  );
  return rows.map((r) => ({ ...r, at: new Date(r.at).toISOString() }));
}
