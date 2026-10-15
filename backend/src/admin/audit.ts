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
 * mechanism — there is no CLS/AsyncLocalStorage carrying "the current request's
 * open transaction" the way DMS's requestContext.ts does. writeAudit() below
 * therefore takes an OPTIONAL trailing `existingClient` parameter: pass one
 * (already `BEGIN`'d) to make this audit write atomic with your own domain
 * writes on that same client — see admin/access.ts's addUserToGroup /
 * removeUserFromGroup for the pattern — and writeAudit will run its lock+insert
 * against it without opening or committing its own transaction, leaving that
 * entirely to you. Omit it (as most call sites still do, where the write isn't
 * cheaply reachable on one connection, e.g. applyAccess()'s cross-DB DMS calls)
 * and writeAudit falls back to today's behavior: its own dedicated transaction,
 * scoped only to the audit write, internally consistent for the hash chain but
 * not atomic with whatever domain mutation it describes.
 *
 * P2-5: closing the gap for every remaining call site would mean building IdP's
 * own version of DMS's ambient-request-transaction infrastructure (CLS-carried
 * transaction, auto-joined by every query) — the `existingClient` parameter is
 * the narrower, already-available tool for the call sites where the caller
 * already holds one connection for both writes.
 */

import { clientIpOf } from '../http/client-ip.js';
import { isPlatformAdminEmail } from '../auth/platform-admin.js';
import crypto from 'node:crypto';
import type { Request } from 'express';
import type pg from 'pg';
import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';
import { IDP_CONFIG } from '../config.js';
import { buildAuditFilter, type AuditFilterInput } from './services/audit-filters.js';

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

interface ChainFields {
  sequenceNumber: string;
  createdAtIso: string;
  action: string;
  actorEmail: string;
  target: string;
  detail: unknown;
  ip: string;
  userAgent: string;
  previousHash: string | null;
}

/** Rows written from now on. Rows written before migration 013 are version 1. */
const CURRENT_HASH_VERSION = 2;

/**
 * Canonical string hashed (via HMAC-SHA256) into entry_hash — every field that
 * identifies the row, plus previous_hash, so altering ANY of them (or reordering
 * the chain) is detectable.
 *
 * VERSION 1 (P2-6 defect 1) concatenated the fields with NOTHING between them.
 * That is ambiguous: `action = "user.disa"` with `target = "ble:bob@x"` produces
 * byte-for-byte the same HMAC input as `action = "user.disable"` with
 * `target = "bob@x"`. Anyone able to write rows could shift a field boundary and
 * leave the chain verifying clean — a canonicalization hole in the one function
 * whose entire purpose is to be canonical.
 *
 * VERSION 2 hashes a JSON array of the same fields. Array encoding is
 * unambiguous: every element is delimited and every string is escaped, so no two
 * different field splits can collide.
 *
 * Version 1 is still computed, for verification only, because rows hashed under
 * it must stay verifiable. Rewriting historical rows to the new algorithm would
 * itself be tampering with the audit trail, and would destroy the only evidence
 * that those rows are unmodified.
 */
function chainData(fields: ChainFields, version: number): string {
  if (version === 1) {
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
  return canonicalJson([
    'v2',
    fields.sequenceNumber,
    fields.createdAtIso,
    fields.action,
    fields.actorEmail,
    fields.target,
    fields.detail,
    fields.ip,
    fields.userAgent,
    fields.previousHash,
  ]);
}

export async function writeAudit(
  req: Request,
  actorEmail: string,
  action: string,
  target: string,
  detail: Record<string, unknown> = {},
  /** Pass an already-open, already-BEGIN'd client to make this audit write
   *  atomic with a caller's own domain-mutation writes on that same client
   *  (see e.g. admin/access.ts's addUserToGroup/removeUserFromGroup) — this
   *  function then does its lock+insert against it and leaves BEGIN/COMMIT/
   *  ROLLBACK entirely to the caller. Omit it (the default, and every
   *  existing call site) to keep today's behavior: writeAudit opens and
   *  commits its own dedicated transaction, scoped only to the audit write. */
  existingClient?: pg.PoolClient,
): Promise<void> {
  // The platform administrator leaves no attributable trace: the action is still
  // recorded (the chain stays gap-free and the platform stays accountable in
  // aggregate) but under an anonymous actor, with no address or browser.
  const anonymous = await isPlatformAdminEmail(actorEmail);
  if (anonymous) actorEmail = 'platform';
  const ip = anonymous ? '' : clientIpOf(req);
  const userAgent = anonymous ? '' : String(req.get('user-agent') ?? '').slice(0, 300);
  const createdAt = new Date();

  const ownsTransaction = !existingClient;
  const client = existingClient ?? (await pool.connect());
  try {
    if (ownsTransaction) {
      await client.query('BEGIN');
    }
    // Serializes writers on the single global chain so it can't fork under
    // concurrency (mirrors DMS's per-tenant pg_advisory_xact_lock, collapsed
    // to one lock key since IdP has no tenants). Released automatically at
    // COMMIT/ROLLBACK — the caller's, when this joins an existing transaction.
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
        chainData(
          {
            sequenceNumber,
            createdAtIso: createdAt.toISOString(),
            action,
            actorEmail,
            target,
            detail,
            ip,
            userAgent,
            previousHash,
          },
          CURRENT_HASH_VERSION,
        ),
      )
      .digest('hex');

    await client.query(
      `INSERT INTO idp_admin_audit
         (actor_email, action, target, detail, ip, user_agent, sequence_number, previous_hash, entry_hash, created_at, hash_version)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [actorEmail, action, target, JSON.stringify(detail), ip, userAgent, sequenceNumber, previousHash, entryHash, createdAt, CURRENT_HASH_VERSION],
    );

    /**
     * P2-6 defect 2: advance the chain-head anchor in the SAME transaction, under
     * the same advisory lock.
     *
     * Without an anchor, deleting rows from EITHER end of the chain left something
     * that verified perfectly: the loop skipped the linkage check for the first row
     * and nothing recorded what the last row was supposed to be. With it, both
     * ends are pinned by a value written at the time the chain grew.
     *
     * The `GREATEST` guard means a replayed or out-of-order write can never move
     * the anchor backwards, which would otherwise hide a truncation.
     */
    await client.query(
      `INSERT INTO idp_admin_audit_anchor (id, sequence_number, entry_hash, updated_at)
       VALUES (1, $1, $2, NOW())
       ON CONFLICT (id) DO UPDATE
         SET sequence_number = EXCLUDED.sequence_number,
             entry_hash = EXCLUDED.entry_hash,
             updated_at = NOW()
         WHERE EXCLUDED.sequence_number >= idp_admin_audit_anchor.sequence_number`,
      [sequenceNumber, entryHash],
    );

    if (ownsTransaction) {
      await client.query('COMMIT');
    }
  } catch (err) {
    if (ownsTransaction) {
      await client.query('ROLLBACK').catch(() => {});
    }
    throw err;
  } finally {
    if (ownsTransaction) {
      client.release();
    }
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

/** One page of the trail, newest first, narrowed by the Audit page's filters (admin/services/audit-filters.ts). */
export async function listAudit(filter: AuditFilterInput, limit = 100, offset = 0): Promise<AuditRow[]> {
  const f = buildAuditFilter(filter);
  const { rows } = await pool.query<AuditRow>(
    `SELECT id, actor_email, action, target, detail, ip, user_agent, sequence_number, created_at
     FROM idp_admin_audit
     ${f.where}
     ORDER BY sequence_number DESC LIMIT $${f.params.length + 1} OFFSET $${f.params.length + 2}`,
    [...f.params, limit, offset],
  );
  return rows;
}

export async function countAudit(filter: AuditFilterInput): Promise<number> {
  const f = buildAuditFilter(filter);
  const { rows } = await pool.query<{ count: string }>(`SELECT COUNT(*) FROM idp_admin_audit ${f.where}`, f.params);
  return Number(rows[0].count);
}

/** Every action that appears in the visible trail, for the filter's drop-down (so it only offers what exists). */
export async function distinctAuditActions(): Promise<string[]> {
  const f = buildAuditFilter({});
  const { rows } = await pool.query<{ action: string }>(`SELECT DISTINCT action FROM idp_admin_audit ${f.where} ORDER BY action`, f.params);
  return rows.map((r) => r.action);
}

export async function recentAudit(limit = 100, offset = 0): Promise<AuditRow[]> {
  return listAudit({}, limit, offset);
}

/** Total row count — backs the admin audit page's real pagination (it used
 *  to hard-cap at a flat `?limit=100` with no way to see further back). */
export async function countAuditRows(): Promise<number> {
  return countAudit({});
}

/**
 * What a verification found wrong, one entry per problem.
 *
 *   hash      the row's stored entry_hash is not the HMAC of its own content (the row was edited)
 *   linkage   the row's previous_hash is not the entry_hash of the row before it (a row between them was removed or inserted)
 *   ordering  sequence numbers do not strictly increase (rows renumbered or reordered)
 *   head      the earliest surviving row is not the start of the chain (earlier rows were deleted)
 *   tail      the end of the chain does not match the anchor (rows were deleted from the end, or the last row was edited)
 *   empty     the table has no rows although the anchor says there were
 *
 * `hash`, `linkage`, `ordering` and `head` can be acknowledged (see acknowledgeChainBreak); `tail` and `empty` cannot, because there is no
 * row to pin an acknowledgement to and they mean recent data is missing: restore it or run the documented anchor reset.
 */
export type ChainBreakKind = 'hash' | 'linkage' | 'ordering' | 'head' | 'tail' | 'empty';

export const ACKNOWLEDGEABLE_KINDS: readonly ChainBreakKind[] = ['hash', 'linkage', 'ordering', 'head'];

export interface ChainBreak {
  sequenceNumber: string;
  kind: ChainBreakKind;
  message: string;
  acknowledgeable: boolean;
  /** Set when a recorded acknowledgement still covers this break. */
  acknowledged?: { by: string; at: string; reason: string };
  /** What an acknowledgement is pinned to; internal, never sent to the browser. */
  pin?: { entryHash: string; previousHash: string | null; fingerprint: string };
}

export interface ChainVerification {
  /** No break that is not acknowledged. Acknowledged breaks are still listed in `breaks`. */
  valid: boolean;
  checked: number;
  /** Inclusive sequence-number range actually verified. */
  fromSequence?: string;
  toSequence?: string;
  legacyCount: number;
  /** The first break nobody has acknowledged (kept for callers that only want one number). */
  brokenAtSequence?: string;
  /** Every break found (at most MAX_REPORTED_BREAKS), acknowledged or not. */
  breaks: ChainBreak[];
  openBreaks: number;
  acknowledgedBreaks: number;
  /** More breaks exist than are listed. */
  truncated: boolean;
  message: string;
}

/** Rows pulled per round trip. Bounded memory, and small enough that a
 *  verification never holds a pool connection for an unbounded scan (P1-21). */
const VERIFY_BATCH_SIZE = 1000;

/** A damaged chain can have a break on every row; the report stays readable and the memory bounded. */
export const MAX_REPORTED_BREAKS = 50;

interface AuditChainRow {
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
  hash_version: number;
}

function recomputeHash(r: AuditChainRow): string {
  return crypto
    .createHmac('sha256', IDP_CONFIG.auditHmacSecret)
    .update(
      chainData(
        {
          sequenceNumber: r.sequence_number,
          createdAtIso: new Date(r.created_at).toISOString(),
          action: r.action,
          actorEmail: r.actor_email,
          target: r.target,
          detail: r.detail,
          ip: r.ip,
          userAgent: r.user_agent,
          previousHash: r.previous_hash,
        },
        // Per row, not globally: rows written before migration 013 are version 1
        // and must be verified with the algorithm they were written under.
        Number(r.hash_version) || 1,
      ),
    )
    .digest('hex');
}

/**
 * A fingerprint of everything in the row as it stands. An acknowledgement is pinned to it, so a row that is edited AFTER it was acknowledged (even
 * without touching its stored hashes, which is all an attacker without the HMAC key can do) is a new, unexplained break.
 */
export function rowFingerprint(r: AuditChainRow): string {
  return crypto
    .createHash('sha256')
    .update(
      canonicalJson([
        'fp1',
        r.sequence_number,
        new Date(r.created_at).toISOString(),
        r.actor_email,
        r.action,
        r.target,
        r.detail,
        r.ip,
        r.user_agent,
        r.previous_hash,
        r.entry_hash,
        Number(r.hash_version) || 1,
      ]),
    )
    .digest('hex');
}

interface AckRow {
  sequence_number: string;
  kind: string;
  entry_hash: string;
  previous_hash: string | null;
  row_fingerprint: string;
  reason: string;
  acknowledged_by: string;
  acknowledged_at: Date;
}

/** Recorded acknowledgements. A read failure is treated as "none": the chain then reads as broken, never healthier than it is. */
async function loadAcknowledgements(): Promise<AckRow[]> {
  try {
    const { rows } = await pool.query<AckRow>(
      `SELECT sequence_number::text AS sequence_number, kind, entry_hash, previous_hash, row_fingerprint, reason, acknowledged_by, acknowledged_at
         FROM idp_audit_chain_acknowledgements`,
    );
    return rows;
  } catch (err) {
    // Migration 021 not applied yet, or the table unreadable. Say so in the log; do not hide the break.
    logger.warn({ err }, '[idp:audit] could not read chain acknowledgements; treating every break as unacknowledged');
    return [];
  }
}

function applyAcknowledgements(breaks: ChainBreak[], acks: AckRow[]): void {
  for (const b of breaks) {
    if (!b.pin) continue;
    const hit = acks.find(
      (a) =>
        a.sequence_number === b.sequenceNumber &&
        a.kind === b.kind &&
        a.entry_hash === b.pin!.entryHash &&
        (a.previous_hash ?? null) === (b.pin!.previousHash ?? null) &&
        a.row_fingerprint === b.pin!.fingerprint,
    );
    if (hit) b.acknowledged = { by: hit.acknowledged_by, at: new Date(hit.acknowledged_at).toISOString(), reason: hit.reason };
  }
}

/**
 * Walks idp_admin_audit in sequence order and reports EVERY place it no longer holds (it used to stop at the first, which hid whether a
 * known old break was the only one). It confirms:
 *   (1) each non-legacy row's stored entry_hash matches a freshly recomputed
 *       HMAC, using that row's own hash_version;
 *   (2) each row's previous_hash points at the prior row's entry_hash;
 *   (3) the FIRST row really is the first — previous_hash IS NULL — and the last
 *       row matches the anchor. This is what P2-6 defect 2 was about: the old
 *       loop skipped the linkage check for i === 0 and asserted nothing about
 *       either end, so deleting rows 1..N produced a chain that verified clean;
 *   (4) sequence numbers strictly increase (not contiguous: see below).
 *
 * After a break the walk carries on from the row's STORED hash, so one edited row yields one `hash` break and not a cascade down the
 * rest of the chain.
 *
 * Legacy rows (migrations/007_phase_e.sql) are excluded from (1) — there is no
 * secret to verify them against — but are still subject to (2)–(4).
 *
 * Batched in VERIFY_BATCH_SIZE chunks: this used to SELECT the entire table and
 * materialize it from a synchronous admin GET, which at scale means an OOM or a
 * timeout while holding a pool connection.
 *
 * Sequence numbers are strictly INCREASING, deliberately not contiguous. `sequence_number` comes from a Postgres sequence consumed by
 * `nextval()` inside writeAudit's own transaction, and nextval is NOT transactional: any audit write that rolls back permanently burns its
 * number and leaves a hole in a chain nobody tampered with. A genuine deletion from the middle is already caught by linkage (2): the
 * surviving successor's previous_hash points at an entry_hash no remaining row holds. DMS's own audit chain checks exactly this.
 */
export async function verifyAuditChain(): Promise<ChainVerification> {
  const { rows: anchorRows } = await pool.query<{ sequence_number: string; entry_hash: string }>(
    'SELECT sequence_number, entry_hash FROM idp_admin_audit_anchor WHERE id = 1',
  );
  const anchor = anchorRows[0];

  const breaks: ChainBreak[] = [];
  let breakTotal = 0;
  const record = (b: ChainBreak): void => {
    breakTotal++;
    if (breaks.length < MAX_REPORTED_BREAKS) breaks.push(b);
  };
  const rowBreak = (r: AuditChainRow, kind: ChainBreakKind, message: string): ChainBreak => ({
    sequenceNumber: r.sequence_number,
    kind,
    message,
    acknowledgeable: ACKNOWLEDGEABLE_KINDS.includes(kind),
    pin: { entryHash: r.entry_hash, previousHash: r.previous_hash, fingerprint: rowFingerprint(r) },
  });

  let expectedPrevious: string | null = null;
  let previousSequence: bigint | null = null;
  let legacyCount = 0;
  let checked = 0;
  let firstSequence: string | undefined;
  let lastRow: AuditChainRow | undefined;
  let after = '0';

  for (;;) {
    const { rows } = await pool.query<AuditChainRow>(
      `SELECT sequence_number, previous_hash, entry_hash, actor_email, action, target, detail,
              ip, user_agent, created_at, hash_version
         FROM idp_admin_audit
        WHERE sequence_number > $1
        ORDER BY sequence_number ASC
        LIMIT $2`,
      [after, VERIFY_BATCH_SIZE],
    );
    if (rows.length === 0) break;

    for (const r of rows) {
      if (checked === 0) {
        // (3) first row: must genuinely be the head of the chain.
        firstSequence = r.sequence_number;
        if (r.previous_hash !== null) {
          record(
            rowBreak(
              r,
              'head',
              `The earliest surviving entry (sequence ${r.sequence_number}) has a previous_hash, so it is not the start of the chain: earlier entries have been deleted.`,
            ),
          );
        }
      } else {
        // (2) linkage.
        if (r.previous_hash !== expectedPrevious) {
          record(rowBreak(r, 'linkage', `Chain linkage broken at sequence ${r.sequence_number}: previous_hash does not match the prior row's entry_hash.`));
        }
        // (4) strictly increasing.
        const current = BigInt(r.sequence_number);
        if (previousSequence !== null && current <= previousSequence) {
          record(
            rowBreak(
              r,
              'ordering',
              `Sequence ordering violated at ${r.sequence_number} (previous was ${previousSequence}): rows have been reordered or renumbered.`,
            ),
          );
        }
      }

      // (1) hash.
      if (r.entry_hash.startsWith(LEGACY_PREFIX)) {
        legacyCount++;
      } else if (recomputeHash(r) !== r.entry_hash) {
        record(
          rowBreak(r, 'hash', `Entry ${r.sequence_number} was modified: its stored entry_hash does not match the recomputed HMAC (hash_version ${r.hash_version}).`),
        );
      }

      expectedPrevious = r.entry_hash;
      previousSequence = BigInt(r.sequence_number);
      lastRow = r;
      checked++;
      after = r.sequence_number;
    }

    if (rows.length < VERIFY_BATCH_SIZE) break;
  }

  if (checked === 0 && anchor) {
    // An anchor with no rows behind it means the table was emptied.
    record({
      sequenceNumber: anchor.sequence_number,
      kind: 'empty',
      acknowledgeable: false,
      message: `The audit table is empty, but the anchor records a chain head at sequence ${anchor.sequence_number}. Every entry has been deleted.`,
    });
  }

  // (3) tail: the last surviving row must be the one the anchor recorded.
  if (anchor && lastRow) {
    if (BigInt(anchor.sequence_number) > BigInt(lastRow.sequence_number)) {
      record({
        sequenceNumber: lastRow.sequence_number,
        kind: 'tail',
        acknowledgeable: false,
        message: `The chain ends at sequence ${lastRow.sequence_number} but the anchor records ${anchor.sequence_number}: entries have been deleted from the end of the chain.`,
      });
    } else if (BigInt(anchor.sequence_number) === BigInt(lastRow.sequence_number) && anchor.entry_hash !== lastRow.entry_hash) {
      record({
        sequenceNumber: lastRow.sequence_number,
        kind: 'tail',
        acknowledgeable: false,
        message: `The final entry's hash does not match the anchor for sequence ${lastRow.sequence_number}: it has been modified.`,
      });
    }
  }

  applyAcknowledgements(breaks, breakTotal > 0 ? await loadAcknowledgements() : []);
  const open = breaks.filter((b) => !b.acknowledged);
  const acknowledgedBreaks = breaks.length - open.length;
  // Breaks beyond the reporting limit were not matched against acknowledgements, so they count as open.
  const openBreaks = open.length + (breakTotal - breaks.length);
  const truncated = breakTotal > breaks.length;

  const base = { checked, fromSequence: firstSequence, toSequence: lastRow?.sequence_number, legacyCount, breaks, acknowledgedBreaks, truncated };

  if (checked === 0 && !anchor) {
    return { ...base, valid: true, openBreaks: 0, message: 'No audit entries to verify.' };
  }
  if (openBreaks > 0) {
    const first = open[0] ?? breaks[0];
    return {
      ...base,
      valid: false,
      openBreaks,
      brokenAtSequence: first?.sequenceNumber,
      message:
        `${openBreaks} problem(s) in the audit chain` +
        (acknowledgedBreaks > 0 ? ` (${acknowledgedBreaks} more are acknowledged and explained)` : '') +
        `. First: ${first?.message ?? 'see the list'}`,
    };
  }

  const anchorNote = anchor
    ? 'both ends pinned against the chain anchor'
    : 'NO anchor row exists, so truncation of the whole chain cannot be ruled out — run migration 013';
  return {
    ...base,
    valid: true,
    openBreaks: 0,
    message:
      `Verified ${checked} audit entries, sequence ${firstSequence}–${lastRow?.sequence_number} ` +
      `(${legacyCount} legacy, unverifiable pre-chain row(s) excluded from HMAC recomputation; ${anchorNote}).` +
      (acknowledgedBreaks > 0 ? ` ${acknowledgedBreaks} historical break(s) are on record and acknowledged.` : ''),
  };
}

export class ChainAcknowledgementError extends Error {
  constructor(
    public readonly status: 404 | 409 | 422,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ChainAcknowledgementError';
  }
}

export const MIN_ACK_REASON_LENGTH = 20;

/**
 * Record that a break the verifier reports right now is known, explained and historical.
 *
 * Only a break that is CURRENTLY reported can be acknowledged (nothing can be pre-acknowledged), only the kinds that point at a row, and
 * the acknowledgement is pinned to that row as it is today. The break stays listed; nothing in the chain is rewritten. The acknowledgement
 * is itself an entry appended to the chain, in the same transaction as the record, so one cannot exist without the other.
 *
 * `actorEmail` is who is acknowledging; the platform administrator is stored as 'platform' (auth/platform-admin.ts).
 */
export async function acknowledgeChainBreak(
  req: Request,
  actorEmail: string,
  input: { sequenceNumber: string; kind: string; reason: string },
): Promise<ChainVerification> {
  const reason = String(input.reason ?? '').trim();
  if (reason.length < MIN_ACK_REASON_LENGTH || reason.length > 2000) {
    throw new ChainAcknowledgementError(422, 'ERR-VALIDATION-FAILED', `Say why this break is known and harmless (${MIN_ACK_REASON_LENGTH} to 2000 characters).`);
  }
  if (!/^\d{1,18}$/.test(String(input.sequenceNumber))) {
    throw new ChainAcknowledgementError(422, 'ERR-VALIDATION-FAILED', 'sequenceNumber must be a whole number.');
  }
  const current = await verifyAuditChain();
  const target = current.breaks.find((b) => b.sequenceNumber === String(input.sequenceNumber) && b.kind === input.kind);
  if (!target) throw new ChainAcknowledgementError(404, 'ERR-CHAIN-BREAK-NOT-FOUND', 'That break is not currently reported.');
  if (!target.acknowledgeable || !target.pin) {
    throw new ChainAcknowledgementError(422, 'ERR-CHAIN-BREAK-NOT-ACKNOWLEDGEABLE', 'That kind of break cannot be acknowledged: it means recent entries are missing. Restore the database from a backup.');
  }
  if (target.acknowledged) throw new ChainAcknowledgementError(409, 'ERR-CHAIN-BREAK-ACKNOWLEDGED', 'That break is already acknowledged.');

  const by = (await isPlatformAdminEmail(actorEmail)) ? 'platform' : actorEmail;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO idp_audit_chain_acknowledgements (sequence_number, kind, entry_hash, previous_hash, row_fingerprint, reason, acknowledged_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (sequence_number, kind) DO UPDATE
         SET entry_hash = EXCLUDED.entry_hash, previous_hash = EXCLUDED.previous_hash, row_fingerprint = EXCLUDED.row_fingerprint,
             reason = EXCLUDED.reason, acknowledged_by = EXCLUDED.acknowledged_by, acknowledged_at = NOW()`,
      [target.sequenceNumber, target.kind, target.pin.entryHash, target.pin.previousHash, target.pin.fingerprint, reason, by],
    );
    await writeAudit(req, actorEmail, 'audit.chain_break_acknowledged', `sequence ${target.sequenceNumber}`, { sequenceNumber: target.sequenceNumber, kind: target.kind, reason }, client);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
  return verifyAuditChain();
}
