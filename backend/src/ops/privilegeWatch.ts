/**
 * Detectors for administrator-privilege changes that the owner did not make (event kind `privilege_change_by_non_owner`, ops/securityEvents.ts).
 *
 * Two independent sources, because each one catches what the other cannot:
 *
 *  1. ATTEMPTS. The code paths that change who is an IdP administrator already refuse everyone but the owner (PlatformAdminOnlyError and the console's own
 *     checks). `reportNonOwnerPrivilegeAttempt` turns each refusal into an event (outcome `refused`), so the attempt is recorded and, if repeated, contained.
 *
 *  2. THE RESULT. `scanPrivilegeChanges` (a background job) compares the CURRENT membership of the IdP administrator group with the last snapshot and the
 *     tamper-evident admin audit chain: every person added or removed must have a matching audit row written by the owner (actor `platform`), and no
 *     admin-group audit row may carry any other actor. A change with no such row is outcome `unexplained` (someone changed the table directly); an audit row
 *     by another actor is outcome `applied` (the guard was bypassed and the change took effect). Both are critical and lock SSO at once.
 *
 * The platform administrator account itself is invisible to the console and is excluded from the comparison.
 * No event here carries an address: ids and a masked address only.
 */
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';
import { emitSecurityEvent } from './securityEvents.js';

export function maskEmail(email: string): string {
  const [local = '', domain = ''] = email.trim().toLowerCase().split('@');
  if (!domain) return '***';
  return `${local.slice(0, 1)}***@${domain}`;
}

/**
 * A non-owner tried to change administrator rights and was refused. Fire-and-forget: never throws, never delays the refusal.
 * `email` is only used to find the account (so its sessions can be revoked if the policy says so); it is not put in the event.
 */
export function reportNonOwnerPrivilegeAttempt(actor: { email?: string; userId?: string; sessionId?: string; ip?: string }, operation: string, detail: Record<string, string | number | boolean | null> = {}): void {
  void (async () => {
    let userId = actor.userId;
    if (!userId && actor.email) {
      try {
        const { rows } = await pool.query<{ id: string }>('SELECT id FROM idp_users WHERE lower(email) = lower($1) LIMIT 1', [actor.email]);
        userId = rows[0]?.id;
      } catch {
        /* the event still goes out, without an id */
      }
    }
    emitSecurityEvent({
      kind: 'privilege_change_by_non_owner',
      severity: 'critical',
      actor: { userId, maskedEmail: actor.email ? maskEmail(actor.email) : undefined, sessionId: actor.sessionId, ip: actor.ip },
      operation,
      detail: { outcome: 'refused', ...detail },
    });
  })().catch(() => undefined);
}

// ---- the result scan ---------------------------------------------------------

export interface AuditAdminRow {
  sequence: string;
  actorEmail: string;
  action: string;
  userId: string;
}

export interface DriftFinding {
  outcome: 'applied' | 'unexplained';
  direction: 'added' | 'removed';
  userId: string;
  /** For `applied`: the audit sequence of the row written by someone other than the owner. */
  auditSequence?: string;
  /** For `applied`: who the audit row says did it (never put in an event; used to find the account). */
  actorEmail?: string;
}

/**
 * Pure comparison. `snapshot` and `current` are admin-group member ids (the owner excluded); `rows` are the admin-group audit rows written since the
 * snapshot. A change is EXPLAINED only by a row from actor `platform` for that person in the right direction.
 */
export function classifyPrivilegeChanges(snapshot: readonly string[], current: readonly string[], rows: readonly AuditAdminRow[]): DriftFinding[] {
  const before = new Set(snapshot);
  const after = new Set(current);
  const findings: DriftFinding[] = [];
  const ownerRows = rows.filter((r) => r.actorEmail === 'platform');
  // an audit row by anyone else for an admin-group action is itself the finding (the guard was bypassed)
  for (const r of rows) if (r.actorEmail !== 'platform') findings.push({ outcome: 'applied', direction: r.action.endsWith('.add') ? 'added' : 'removed', userId: r.userId, auditSequence: r.sequence, actorEmail: r.actorEmail });
  for (const id of after) {
    if (before.has(id)) continue;
    if (!ownerRows.some((r) => r.userId === id && r.action === 'user.admin_group.add')) findings.push({ outcome: 'unexplained', direction: 'added', userId: id });
  }
  for (const id of before) {
    if (after.has(id)) continue;
    if (!ownerRows.some((r) => r.userId === id && r.action === 'user.admin_group.remove')) findings.push({ outcome: 'unexplained', direction: 'removed', userId: id });
  }
  return findings;
}

const SNAPSHOT_KEY = 'admin_group_snapshot';

interface Snapshot {
  members: string[];
  /** Highest admin-audit sequence already inspected. */
  auditSequence: string;
  at: string;
}

async function loadSnapshot(): Promise<Snapshot | null> {
  const { rows } = await pool.query<{ value: Snapshot }>('SELECT value FROM security_state WHERE key = $1', [SNAPSHOT_KEY]);
  return rows[0]?.value ?? null;
}

async function saveSnapshot(s: Snapshot): Promise<void> {
  await pool.query(
    `INSERT INTO security_state (key, value, updated_at) VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [SNAPSHOT_KEY, JSON.stringify(s)],
  );
}

/** One pass. The first ever pass records the baseline and reports nothing. Returns the findings (also emitted as events). Throws only if the database cannot be read. */
export async function scanPrivilegeChanges(): Promise<DriftFinding[]> {
  const { rows: members } = await pool.query<{ id: string }>(
    `SELECT ug.user_id::text AS id FROM idp_user_groups ug JOIN idp_users u ON u.id = ug.user_id
      WHERE ug.group_dn = $1 AND NOT u.is_platform_admin ORDER BY 1`,
    [IDP_CONFIG.adminGroup],
  );
  const current = members.map((m) => m.id);
  const { rows: headRows } = await pool.query<{ s: string | null }>('SELECT MAX(sequence_number)::text AS s FROM idp_admin_audit');
  const head = headRows[0]?.s ?? '0';
  const snap = await loadSnapshot();
  if (!snap) {
    await saveSnapshot({ members: current, auditSequence: head, at: new Date().toISOString() });
    return [];
  }
  const { rows: audit } = await pool.query<{ sequence: string; actor_email: string; action: string; user_id: string | null }>(
    `SELECT sequence_number::text AS sequence, actor_email, action, detail->>'userId' AS user_id
       FROM idp_admin_audit
      WHERE sequence_number > $1 AND action IN ('user.admin_group.add', 'user.admin_group.remove')
      ORDER BY sequence_number`,
    [snap.auditSequence],
  );
  const findings = classifyPrivilegeChanges(
    snap.members,
    current,
    audit.map((a) => ({ sequence: a.sequence, actorEmail: a.actor_email, action: a.action, userId: a.user_id ?? '' })),
  );
  for (const f of findings) {
    let actor: { userId?: string; maskedEmail?: string } | undefined;
    if (f.actorEmail) {
      const { rows } = await pool.query<{ id: string }>('SELECT id FROM idp_users WHERE lower(email) = lower($1) LIMIT 1', [f.actorEmail]);
      actor = { userId: rows[0]?.id, maskedEmail: maskEmail(f.actorEmail) };
    }
    emitSecurityEvent({
      kind: 'privilege_change_by_non_owner',
      severity: 'critical',
      actor,
      operation: 'admin_group_membership',
      detail: { outcome: f.outcome, direction: f.direction, subjectUserId: f.userId, auditSequence: f.auditSequence ?? null },
    });
  }
  if (findings.length > 0) logger.error({ count: findings.length }, '[idp:incident:ALERT] IdP administrator membership changed without the owner');
  // Move the baseline forward either way: the finding has been raised once and recorded; the lock (if any) stays until the owner clears it.
  if (findings.length > 0 || current.join() !== snap.members.join() || head !== snap.auditSequence) {
    await saveSnapshot({ members: current, auditSequence: head, at: new Date().toISOString() });
  }
  return findings;
}
