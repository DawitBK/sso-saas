/**
 * The audit-chain head, for the out-of-process tamper watcher's anchor (deploy/tamper/tamper.cjs `anchor`).
 *
 * The watcher records "at sequence S the chain's hash was H" somewhere SSO's database cannot reach (a mailbox, a second file). If someone later rewrites
 * the whole chain in the database, row S no longer has hash H and `anchor verify` says so. Only a hash, a sequence and counts leave SSO here: no row content.
 *
 * Authentication: a shared key kept in the file named by OPS_WATCH_KEY_FILE (unset or unreadable = the endpoint answers 404, as if it did not exist).
 * The caller sends `X-REF-Ops: <unix seconds>.<hex HMAC-SHA256(key, "chain-head|<unix seconds>")>`; a timestamp more than two minutes off is refused.
 * The answer is read-only and reveals nothing the watcher could not also be told by the owner; the key is never logged.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';
import { verifyIncidentChain } from './incidents.js';

const SKEW_SECONDS = 120;

export function signOpsRequest(key: string, unixSeconds: number): string {
  return `${unixSeconds}.${crypto.createHmac('sha256', key).update(`chain-head|${unixSeconds}`).digest('hex')}`;
}

/** True when `header` is a fresh, correct signature for `key`. Constant-time on the MAC. */
export function opsRequestAllowed(header: string | undefined, key: string, nowMs: number = Date.now()): boolean {
  if (!header || !key) return false;
  const dot = header.indexOf('.');
  if (dot < 1) return false;
  const ts = Number(header.slice(0, dot));
  if (!Number.isInteger(ts) || Math.abs(nowMs / 1000 - ts) > SKEW_SECONDS) return false;
  const want = Buffer.from(signOpsRequest(key, ts));
  const got = Buffer.from(header);
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

/** The key from its file, or '' (feature off). Read on each request: it is a few bytes and the file may be rotated. */
export function readOpsKey(file: string = IDP_CONFIG.opsWatchKeyFile): string {
  if (!file) return '';
  try {
    return fs.readFileSync(file, 'utf8').trim();
  } catch {
    return '';
  }
}

export interface ChainHead {
  checkedAt: string;
  audit: { sequence: string | null; hash: string | null; count: number };
  incidents: { sequence: string | null; hash: string | null; count: number; valid: boolean };
  /** Only when `?sequence=` was asked: the hash the audit row at that sequence has now (null when no such row). */
  at?: { sequence: string; hash: string | null };
}

export async function collectChainHead(sequence?: string): Promise<ChainHead> {
  const { rows } = await pool.query<{ sequence_number: string; entry_hash: string }>(
    'SELECT sequence_number::text AS sequence_number, entry_hash FROM idp_admin_audit ORDER BY sequence_number DESC LIMIT 1',
  );
  const { rows: cnt } = await pool.query<{ n: string }>('SELECT COUNT(*)::text AS n FROM idp_admin_audit');
  const inc = await verifyIncidentChain();
  const head: ChainHead = {
    checkedAt: new Date().toISOString(),
    audit: { sequence: rows[0]?.sequence_number ?? null, hash: rows[0]?.entry_hash ?? null, count: Number(cnt[0]?.n ?? 0) },
    incidents: { sequence: inc.headSequence, hash: inc.headHash, count: inc.checked, valid: inc.valid },
  };
  if (sequence && /^\d{1,18}$/.test(sequence)) {
    const { rows: at } = await pool.query<{ entry_hash: string }>('SELECT entry_hash FROM idp_admin_audit WHERE sequence_number = $1', [sequence]);
    head.at = { sequence, hash: at[0]?.entry_hash ?? null };
  }
  return head;
}
