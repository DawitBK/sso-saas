/**
 * Postgres-backed web-session store (idp_web_sessions) — the durable replacement
 * for the in-memory Maps that previously held portal sessions, gateway sessions,
 * and pending OIDC flows. Sessions survive restarts and are shared across
 * instances; expired rows are swept opportunistically on writes.
 */

import crypto from 'node:crypto';
import { pool } from './pool.js';

export type SessionKind = 'portal' | 'gateway' | 'pending_portal' | 'pending_gms' | 'pwchange' | 'mfa' | 'totp_enroll';

/**
 * Delete expired rows. Called from the hourly purge timer in main.ts, NOT from
 * the write paths below.
 *
 * It used to run before every single write — i.e. a table-wide DELETE on every
 * portal login, every GMS gateway handoff, and every parked MFA/password-change
 * step, taking row locks that contend with the very concurrent logins that were
 * issuing it. Nothing depended on that eagerness: every read below already
 * filters on `expires_at > NOW()`, so an unswept expired row is invisible
 * regardless. Moving it to the timer keeps the table bounded without putting a
 * full-table write on the login critical path.
 */
export async function sweepWebSessions(): Promise<void> {
  await pool.query('DELETE FROM idp_web_sessions WHERE expires_at < NOW()');
}

/** Store under a random key (returned). */
export async function putWebSession(kind: SessionKind, payload: unknown, ttlMs: number): Promise<string> {
  const key = crypto.randomBytes(24).toString('hex');
  await pool.query(
    'INSERT INTO idp_web_sessions (kind, key, payload, expires_at) VALUES ($1, $2, $3, $4)',
    [kind, key, JSON.stringify(payload), new Date(Date.now() + ttlMs)],
  );
  return key;
}

/** Store under a caller-chosen key (e.g. an OIDC state value). */
export async function setWebSession(kind: SessionKind, key: string, payload: unknown, ttlMs: number): Promise<void> {
  await pool.query(
    `INSERT INTO idp_web_sessions (kind, key, payload, expires_at) VALUES ($1, $2, $3, $4)
     ON CONFLICT (kind, key) DO UPDATE SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at`,
    [kind, key, JSON.stringify(payload), new Date(Date.now() + ttlMs)],
  );
}

export async function getWebSession<T>(kind: SessionKind, key: string | undefined): Promise<T | undefined> {
  if (!key) return undefined;
  const { rows } = await pool.query<{ payload: T }>(
    'SELECT payload FROM idp_web_sessions WHERE kind = $1 AND key = $2 AND expires_at > NOW()',
    [kind, key],
  );
  return rows[0]?.payload;
}

/** One-time redemption: return the payload and delete the row atomically. */
export async function takeWebSession<T>(kind: SessionKind, key: string | undefined): Promise<T | undefined> {
  if (!key) return undefined;
  const { rows } = await pool.query<{ payload: T }>(
    'DELETE FROM idp_web_sessions WHERE kind = $1 AND key = $2 AND expires_at > NOW() RETURNING payload',
    [kind, key],
  );
  return rows[0]?.payload;
}

export async function dropWebSession(kind: SessionKind, key: string | undefined): Promise<void> {
  if (!key) return;
  await pool.query('DELETE FROM idp_web_sessions WHERE kind = $1 AND key = $2', [kind, key]);
}
