/**
 * Incident response: the subscriber for the security-event bus (ops/securityEvents.ts).
 *
 * On a security event it decides, from the POLICY table below, what to do and does it in this order, so that the most important step cannot be held up by a later one:
 *   1. CONTAIN   write the incident lock (read-only mode, ops/incidentLock.ts) when the policy says so;
 *   2. REVOKE    end the offending actor's sessions and tokens (auth/revoke.ts), never the owner's own;
 *   3. RECORD    one append-only, hash-chained row in `security_incidents` (migration 028) plus a `security.incident` row in the admin audit chain;
 *   4. ALERT     an error-level log line, and one line in the alert spool next to the lock file for the out-of-process watcher (deploy/tamper) to e-mail.
 *
 * What it NEVER does: stop a service, delete anything, disable an account, rotate or destroy any key (the signing-key rotation and the vault master key are
 * manual, owner-confirmed operations), or clear a lock (the owner does that from a terminal with deploy/tamper/tamper.cjs, never through the web).
 *
 * Modes (IDP_CONFIG.incidentResponse): `contain` = all four steps; `alert` = record and alert only (the default outside production, so development is never locked
 * unless someone switches it on); `off` = ignore events.
 *
 * Put NO secret in an incident: events carry ids, a masked address and short facts (see securityEvents.ts).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { Request } from 'express';
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';
import { writeAudit } from '../admin/audit.js';
import { isPlatformAdminId } from '../auth/platform-admin.js';
import { revokeAllSessions } from '../auth/revoke.js';
import { onSecurityEvent, type SecurityEvent } from './securityEvents.js';
import { activeIncidentLock, setMemoryIncidentLock, writeIncidentLock, type IncidentLockInfo } from './incidentLock.js';

export type IncidentMode = 'contain' | 'alert' | 'off';

// ---------------------------------------------------------------------------
// The containment policy
// ---------------------------------------------------------------------------

export interface KindPolicy {
  /** Count window for "repeated". */
  windowMs: number;
  /** Revoke the actor's sessions once this many events of this kind from this actor fall in the window (null: never). */
  revokeAt: number | null;
  /** Lock SSO read-only at this count (null: never). */
  lockAt: number | null;
}

const TEN_MIN = 10 * 60_000;

/**
 * Per event kind. Written down here and in SSO-OPERATIONS.md ("Tamper detection and incident response"); change both together.
 *
 *   owner_op_denied               3 refusals in 10 minutes from one actor: revoke that actor, lock.
 *   owner_op_without_sequence     an attempt to skip the verification sequence: revoke at once, lock at the third.
 *   owner_verification_failed     recorded and counted only (the sequence's own lockout is the defence).
 *   owner_verification_locked     recorded and alerted, no automatic action: the person failing may be the owner.
 *   privilege_change_by_non_owner outcome refused: revoke at once, lock at the third; outcome applied/unexplained (it HAPPENED): revoke and lock at once.
 *   audit_chain_broken            lock at once (evidence may be being destroyed); no actor to revoke.
 *   anything else                 recorded and alerted, no automatic action.
 */
export const POLICY: Record<string, KindPolicy> = {
  owner_op_denied: { windowMs: TEN_MIN, revokeAt: 3, lockAt: 3 },
  owner_op_without_sequence: { windowMs: TEN_MIN, revokeAt: 1, lockAt: 3 },
  owner_verification_failed: { windowMs: TEN_MIN, revokeAt: null, lockAt: null },
  owner_verification_locked: { windowMs: TEN_MIN, revokeAt: null, lockAt: null },
  privilege_change_by_non_owner: { windowMs: TEN_MIN, revokeAt: 1, lockAt: 3 },
  audit_chain_broken: { windowMs: TEN_MIN, revokeAt: null, lockAt: 1 },
};
const DEFAULT_POLICY: KindPolicy = { windowMs: TEN_MIN, revokeAt: null, lockAt: null };

/** A privilege change that actually took effect (not merely refused) is the strongest case: no waiting for repeats. */
function policyFor(event: SecurityEvent): KindPolicy {
  const base = POLICY[event.kind] ?? DEFAULT_POLICY;
  if (event.kind === 'privilege_change_by_non_owner') {
    const outcome = String(event.detail?.outcome ?? 'refused');
    if (outcome === 'applied' || outcome === 'unexplained') return { ...base, revokeAt: 1, lockAt: 1 };
  }
  return base;
}

export interface Decision {
  revoke: boolean;
  lock: boolean;
  count: number;
  /** Why nothing was done, when something was expected. */
  note?: string;
}

/** Pure: what to do for the `count`-th event in the window. `actorIsOwner`: the owner never has their own session revoked or the platform locked over their own action. */
export function decide(event: SecurityEvent, count: number, mode: IncidentMode, actorIsOwner: boolean): Decision {
  const p = policyFor(event);
  if (mode !== 'contain') return { revoke: false, lock: false, count, note: mode === 'alert' ? 'alert-only mode' : undefined };
  if (actorIsOwner) return { revoke: false, lock: false, count, note: 'the actor is the owner: no revoke, no lock' };
  const revoke = Boolean(event.actor?.userId) && p.revokeAt !== null && count >= p.revokeAt;
  const lock = p.lockAt !== null && count >= p.lockAt;
  return { revoke, lock, count };
}

// ---------------------------------------------------------------------------
// The tamper-evident row
// ---------------------------------------------------------------------------

const HASH_VERSION = 1;

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) out[key] = sortKeysDeep((value as Record<string, unknown>)[key]);
    return out;
  }
  return value;
}
const canonicalJson = (v: unknown): string => JSON.stringify(sortKeysDeep(v));

export interface IncidentFields {
  sequenceNumber: string;
  occurredAtIso: string;
  kind: string;
  severity: string;
  actor: unknown;
  operation: string;
  detail: unknown;
  response: unknown;
  previousHash: string | null;
}

/** HMAC-SHA256 over every field and the previous row's hash, keyed with the audit secret (the same key discipline as the admin audit chain). */
export function incidentEntryHash(f: IncidentFields, secret: string = IDP_CONFIG.auditHmacSecret): string {
  return crypto
    .createHmac('sha256', secret)
    .update(canonicalJson(['inc1', f.sequenceNumber, f.occurredAtIso, f.kind, f.severity, f.actor, f.operation, f.detail, f.response, f.previousHash]))
    .digest('hex');
}

export interface RecordedIncident {
  sequenceNumber: string;
  entryHash: string;
}

const CHAIN_LOCK = 'security_incidents';

/** Append one row. Takes a global advisory lock so two simultaneous incidents cannot fork the chain. */
export async function recordIncident(event: SecurityEvent, response: Record<string, unknown>): Promise<RecordedIncident> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [CHAIN_LOCK]);
    const { rows } = await client.query<{ sequence_number: string; entry_hash: string }>(
      'SELECT sequence_number::text AS sequence_number, entry_hash FROM security_incidents ORDER BY sequence_number DESC LIMIT 1',
    );
    const previousHash = rows[0]?.entry_hash ?? null;
    const sequenceNumber = String(BigInt(rows[0]?.sequence_number ?? '0') + 1n);
    const occurredAt = new Date(event.at);
    const actor = event.actor ?? {};
    const detail = event.detail ?? {};
    const operation = (event.operation ?? '').slice(0, 200);
    const entryHash = incidentEntryHash({
      sequenceNumber, occurredAtIso: occurredAt.toISOString(), kind: event.kind, severity: event.severity, actor, operation, detail, response, previousHash,
    });
    await client.query(
      `INSERT INTO security_incidents (sequence_number, occurred_at, kind, severity, actor, operation, detail, response, previous_hash, entry_hash, hash_version)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [sequenceNumber, occurredAt, event.kind.slice(0, 100), event.severity, JSON.stringify(actor), operation, JSON.stringify(detail), JSON.stringify(response), previousHash, entryHash, HASH_VERSION],
    );
    await client.query('COMMIT');
    return { sequenceNumber, entryHash };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export interface IncidentChainResult {
  valid: boolean;
  checked: number;
  /** Sequence of the first row that does not verify. */
  brokenAt?: string;
  problem?: string;
  headSequence: string | null;
  headHash: string | null;
}

/** Walk the whole table in order: every hash recomputed, every link followed. A deleted row is a linkage break; an edited row a hash break. */
export async function verifyIncidentChain(secret: string = IDP_CONFIG.auditHmacSecret): Promise<IncidentChainResult> {
  let after = '0';
  let previous: string | null = null;
  let checked = 0;
  let headSequence: string | null = null;
  let headHash: string | null = null;
  for (;;) {
    const { rows } = await pool.query<{
      sequence_number: string; occurred_at: Date; kind: string; severity: string; actor: unknown; operation: string; detail: unknown; response: unknown;
      previous_hash: string | null; entry_hash: string;
    }>(
      `SELECT sequence_number::text AS sequence_number, occurred_at, kind, severity, actor, operation, detail, response, previous_hash, entry_hash
         FROM security_incidents WHERE sequence_number > $1 ORDER BY sequence_number ASC LIMIT 500`,
      [after],
    );
    if (rows.length === 0) break;
    for (const r of rows) {
      if ((r.previous_hash ?? null) !== previous) {
        return { valid: false, checked, brokenAt: r.sequence_number, problem: 'linkage: a row before this one was removed or inserted', headSequence, headHash };
      }
      const want = incidentEntryHash({
        sequenceNumber: r.sequence_number, occurredAtIso: new Date(r.occurred_at).toISOString(), kind: r.kind, severity: r.severity, actor: r.actor,
        operation: r.operation, detail: r.detail, response: r.response, previousHash: r.previous_hash,
      }, secret);
      if (want !== r.entry_hash) return { valid: false, checked, brokenAt: r.sequence_number, problem: 'hash: this row was edited', headSequence, headHash };
      previous = r.entry_hash;
      headSequence = r.sequence_number;
      headHash = r.entry_hash;
      checked += 1;
      after = r.sequence_number;
    }
  }
  return { valid: true, checked, headSequence, headHash };
}

// ---------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------

export interface IncidentDeps {
  mode: () => IncidentMode;
  now: () => number;
  isOwner: (userId: string) => Promise<boolean>;
  /** Revoke every credential of the account. Resolves to a short, secret-free summary. */
  revoke: (userId: string) => Promise<Record<string, unknown>>;
  /** Create the lock (file when configured, else in-process). Resolves to where, or 'exists' when one was already in force. */
  lock: (reason: string, kind: string) => Promise<'file' | 'memory' | 'exists'>;
  record: (event: SecurityEvent, response: Record<string, unknown>) => Promise<RecordedIncident>;
  audit: (event: SecurityEvent, response: Record<string, unknown>) => Promise<void>;
  spool: (line: Record<string, unknown>) => void;
  alert: (event: SecurityEvent, response: Record<string, unknown>) => void;
}

/** A stand-in request for audit writes made by the system itself: no address, no browser. */
const SYSTEM_REQ = { ip: '', get: () => '' } as unknown as Request;

const counters = new Map<string, number[]>();
const recorded = new Map<string, number[]>();
const MAX_ROWS_PER_KEY_PER_WINDOW = 30;

function actorKey(event: SecurityEvent): string {
  return `${event.kind}|${event.actor?.userId ?? event.actor?.ip ?? 'unknown'}`;
}

function bump(map: Map<string, number[]>, key: string, now: number, windowMs: number): number {
  const list = (map.get(key) ?? []).filter((t) => now - t < windowMs);
  list.push(now);
  map.set(key, list);
  if (map.size > 5000) for (const [k, v] of map) if (v.every((t) => now - t >= windowMs)) map.delete(k);
  return list.length;
}

/** The alert spool: one JSON line per recorded incident, in the folder of the lock file, for the out-of-process watcher. Secret-free by construction. */
export function spoolPath(lockFile: string = IDP_CONFIG.incidentLockFile): string | null {
  const f = lockFile.trim();
  return f ? path.join(path.dirname(f), 'incident-events.jsonl') : null;
}

export const defaultDeps: IncidentDeps = {
  mode: () => IDP_CONFIG.incidentResponse,
  now: () => Date.now(),
  isOwner: (userId) => isPlatformAdminId(userId),
  revoke: async (userId) => {
    const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
    if (!rows[0]) return { revoked: false, reason: 'account not found' };
    const r = await revokeAllSessions(userId, rows[0].email);
    return { revoked: true, oidcArtifacts: r.oidcArtifacts, portalSessions: r.portalSessions, gatewaySessions: r.gatewaySessions, gmsSessions: r.gmsSessions, dmsNotified: r.dmsNotified };
  },
  lock: async (reason, kind) => {
    if (activeIncidentLock(IDP_CONFIG.incidentLockFile)) return 'exists';
    if (IDP_CONFIG.incidentLockFile) return writeIncidentLock(IDP_CONFIG.incidentLockFile, { reason, kind }) ? 'file' : 'exists';
    setMemoryIncidentLock({ reason, kind });
    return 'memory';
  },
  record: recordIncident,
  audit: async (event, response) => {
    await writeAudit(SYSTEM_REQ, 'system', 'security.incident', event.kind, { severity: event.severity, operation: event.operation ?? '', decision: response.decision ?? '', actorUserId: event.actor?.userId ?? '' });
  },
  spool: (line) => {
    const file = spoolPath();
    if (!file) return;
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.appendFileSync(file, `${JSON.stringify(line)}\n`);
    } catch (err) {
      logger.warn({ err }, '[idp:incident] could not append to the alert spool');
    }
  },
  alert: (event, response) => {
    logger.error({ kind: event.kind, severity: event.severity, decision: response.decision, locked: response.locked, revoked: response.revoked }, '[idp:incident:ALERT] security incident');
  },
};

/** The handler for one event. Exported with injectable steps so the policy is testable without a database; every step is isolated so one failing never skips the next. */
export function createIncidentHandler(deps: IncidentDeps = defaultDeps): (event: SecurityEvent) => Promise<void> {
  return async (event) => {
    const mode = deps.mode();
    if (mode === 'off') return;
    if (event.severity === 'info') return;
    const now = deps.now();
    const policy = policyFor(event);
    const key = actorKey(event);
    const count = bump(counters, key, now, policy.windowMs);
    let owner = false;
    if (event.actor?.userId) {
      try {
        owner = await deps.isOwner(event.actor.userId);
      } catch {
        owner = false; // cannot tell: treat as not the owner (containment still must work), the alert says so
      }
    }
    const d = decide(event, count, mode, owner);
    const response: Record<string, unknown> = { mode, decision: d.revoke && d.lock ? 'revoke+lock' : d.lock ? 'lock' : d.revoke ? 'revoke' : 'alert', count: d.count };
    if (d.note) response.note = d.note;
    if (owner) response.actorIsOwner = true;

    // 1 contain
    if (d.lock) {
      try {
        const where = await deps.lock(`${event.kind}${event.operation ? ` (${event.operation})` : ''}`, event.kind);
        response.locked = true;
        response.lockWhere = where;
      } catch (err) {
        response.locked = false;
        response.lockError = String((err as Error)?.message ?? err).slice(0, 120);
        logger.error({ err }, '[idp:incident:ALERT] the incident lock could NOT be written');
      }
    }
    // 2 revoke
    if (d.revoke && event.actor?.userId) {
      try {
        response.revoked = true;
        response.revocation = await deps.revoke(event.actor.userId);
      } catch (err) {
        response.revoked = false;
        response.revokeError = String((err as Error)?.message ?? err).slice(0, 120);
        logger.error({ err }, '[idp:incident:ALERT] the actor’s sessions could NOT be revoked');
      }
    }
    // 3 record (rate-limited so an event storm cannot flood the table; the counters above keep running)
    const rows = bump(recorded, key, now, TEN_MIN);
    if (rows <= MAX_ROWS_PER_KEY_PER_WINDOW) {
      try {
        const rec = await deps.record(event, response);
        response.sequence = rec.sequenceNumber;
      } catch (err) {
        logger.error({ err }, '[idp:incident:ALERT] the incident could not be recorded');
      }
      try {
        await deps.audit(event, response);
      } catch (err) {
        logger.warn({ err }, '[idp:incident] the admin audit row for the incident could not be written');
      }
    } else if (rows === MAX_ROWS_PER_KEY_PER_WINDOW + 1) {
      logger.error({ kind: event.kind }, '[idp:incident:ALERT] event storm: further events of this kind from this actor are counted but not recorded for ten minutes');
    }
    // 4 alert
    try {
      deps.spool({ at: event.at, kind: event.kind, severity: event.severity, operation: event.operation ?? '', decision: response.decision, locked: response.locked ?? false, revoked: response.revoked ?? false, sequence: response.sequence ?? null, source: 'sso' });
      deps.alert(event, response);
    } catch (err) {
      logger.warn({ err }, '[idp:incident] alerting failed');
    }
  };
}

let unsubscribe: (() => void) | null = null;

/** Subscribe the real handler to the bus (called once from main.ts). */
export function startIncidentResponse(): void {
  if (unsubscribe) return;
  unsubscribe = onSecurityEvent(createIncidentHandler());
  logger.info({ mode: IDP_CONFIG.incidentResponse, lockFile: IDP_CONFIG.incidentLockFile ? path.basename(IDP_CONFIG.incidentLockFile) : '(none: in-process lock only)' }, '[idp:incident] incident response started');
}

/** Test hook. */
export function resetIncidentState(): void {
  counters.clear();
  recorded.clear();
  if (unsubscribe) unsubscribe();
  unsubscribe = null;
}

// ---------------------------------------------------------------------------
// Reading, for the console
// ---------------------------------------------------------------------------

export interface IncidentListItem {
  sequence: string;
  occurredAt: string;
  kind: string;
  severity: string;
  actor: Record<string, unknown>;
  operation: string;
  detail: Record<string, unknown>;
  response: Record<string, unknown>;
}

export async function listIncidents(limit = 100, offset = 0): Promise<{ items: IncidentListItem[]; total: number }> {
  const [list, count] = await Promise.all([
    pool.query(
      `SELECT sequence_number::text AS sequence, occurred_at, kind, severity, actor, operation, detail, response
         FROM security_incidents ORDER BY sequence_number DESC LIMIT $1 OFFSET $2`,
      [Math.min(Math.max(limit, 1), 500), Math.max(offset, 0)],
    ),
    pool.query<{ n: string }>('SELECT COUNT(*)::text AS n FROM security_incidents'),
  ]);
  return {
    total: Number(count.rows[0]?.n ?? 0),
    items: list.rows.map((r) => ({
      sequence: String(r.sequence), occurredAt: new Date(r.occurred_at).toISOString(), kind: r.kind, severity: r.severity,
      actor: r.actor ?? {}, operation: r.operation ?? '', detail: r.detail ?? {}, response: r.response ?? {},
    })),
  };
}

export interface LockStatus {
  /** Whether an INCIDENT_LOCK_FILE is configured at all (off in development). */
  configured: boolean;
  locked: boolean;
  info: IncidentLockInfo | null;
  /** `file`, or `memory` for an in-process lock that lasts until the next restart. */
  kind: 'file' | 'memory' | 'none';
  responseMode: IncidentMode;
}

export function lockStatus(): LockStatus {
  const file = IDP_CONFIG.incidentLockFile;
  const info = activeIncidentLock(file);
  return {
    configured: Boolean(file),
    locked: info !== null,
    info,
    kind: info === null ? 'none' : file && fs.existsSync(file) ? 'file' : 'memory',
    responseMode: IDP_CONFIG.incidentResponse,
  };
}
