/**
 * Owner authorisation tickets: what the sequence produces and what an owner-only operation consumes.
 *
 * A ticket is a compact JWS (RS256, header typ `kcms-owner-ticket+jwt`) signed with SSO's OIDC signing key, so another system (DMS) can verify it
 * against the JWKS it already trusts. Claims: iss (the issuer), aud (`sso` or `dms`: the system that performs the operation), sub (the owner's
 * account id), jti (one per ticket), op (the operation key), th (hash of what it acts on, when the operation has a target), sid (hash of the portal
 * session it was issued to), iat, exp (at most TICKET_TTL_SECONDS later).
 *
 * Every ticket is also a database row (owner_verification_tickets) with a state machine: issued -> reserved (a request is using it) -> consumed.
 * Reserving is atomic, so two requests carrying one ticket cannot both pass. A request refused for a reason that changed nothing (any 4xx)
 * releases the ticket back to issued until it expires; one that succeeded, or died on the server, leaves it consumed. DMS keeps its own single-use
 * memory of the jti, because the row here is not shared with it.
 */
import crypto from 'node:crypto';
import { SignJWT, importJWK, jwtVerify, type JWK } from 'jose';
import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { loadSigningJwks } from '../jwks.js';
import { TICKET_TTL_SECONDS } from './policy.js';
import type { OwnerAudience } from './registry.js';

export const OWNER_TICKET_TYP = 'kcms-owner-ticket+jwt';

export interface IssuedTicket {
  ticket: string;
  jti: string;
  expiresAt: Date;
}

export async function issueTicket(input: {
  accountId: string;
  sessionHash: string;
  operation: string;
  targetHash: string | null;
  audience: OwnerAudience;
}): Promise<IssuedTicket> {
  const [jwk] = await loadSigningJwks();
  if (!jwk) throw new Error('no signing key available');
  const key = await importJWK(jwk as unknown as JWK, 'RS256');
  const jti = crypto.randomUUID();
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + TICKET_TTL_SECONDS;
  const ticket = await new SignJWT({ op: input.operation, sid: input.sessionHash, ...(input.targetHash ? { th: input.targetHash } : {}) })
    .setProtectedHeader({ alg: 'RS256', typ: OWNER_TICKET_TYP, kid: String(jwk.kid) })
    .setIssuer(IDP_CONFIG.issuer)
    .setAudience(input.audience)
    .setSubject(input.accountId)
    .setJti(jti)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(key);
  const expiresAt = new Date(exp * 1000);
  await pool.query(
    'INSERT INTO owner_verification_tickets (jti, session_hash, operation_key, target_hash, audience, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
    [jti, input.sessionHash, input.operation, input.targetHash, input.audience, expiresAt],
  );
  return { ticket, jti, expiresAt };
}

export type TicketProblem =
  | 'malformed'
  | 'signature'
  | 'expired'
  | 'wrong_operation'
  | 'wrong_target'
  | 'wrong_session'
  | 'wrong_account'
  | 'wrong_audience'
  | 'unknown'
  | 'used';

function publicOnly(jwk: Record<string, unknown>): JWK {
  const copy: Record<string, unknown> = { ...jwk };
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) delete copy[field];
  return copy as unknown as JWK;
}

/**
 * Verify a ticket for an operation performed here and RESERVE it atomically. Returns the jti, or the reason. Never throws for a bad ticket.
 * The caller must call finishTicket(jti, statusCode) when the request ends.
 */
export async function verifyAndReserveTicket(
  token: string,
  expected: { operation: string; targetHash: string | null; sessionHash: string; accountId: string },
): Promise<{ jti: string } | { problem: TicketProblem }> {
  if (!token || token.length > 4096) return { problem: 'malformed' };
  let header: { kid?: string; typ?: string };
  try {
    header = JSON.parse(Buffer.from(token.split('.')[0] ?? '', 'base64url').toString('utf8'));
  } catch {
    return { problem: 'malformed' };
  }
  if (header.typ !== OWNER_TICKET_TYP) return { problem: 'malformed' };
  const jwks = await loadSigningJwks();
  const jwk = jwks.find((k) => k.kid === header.kid);
  if (!jwk) return { problem: 'signature' };
  let payload: Record<string, unknown>;
  try {
    const key = await importJWK(publicOnly(jwk), 'RS256');
    ({ payload } = await jwtVerify(token, key, { issuer: IDP_CONFIG.issuer, algorithms: ['RS256'], typ: OWNER_TICKET_TYP }));
  } catch (err) {
    const code = (err as { code?: string }).code;
    return { problem: code === 'ERR_JWT_EXPIRED' ? 'expired' : 'signature' };
  }
  const iat = Number(payload.iat);
  const exp = Number(payload.exp);
  if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp - iat > TICKET_TTL_SECONDS + 30) return { problem: 'malformed' };
  if (payload.aud !== 'sso') return { problem: 'wrong_audience' };
  if (payload.op !== expected.operation) return { problem: 'wrong_operation' };
  if ((payload.th ?? null) !== expected.targetHash) return { problem: 'wrong_target' };
  if (payload.sid !== expected.sessionHash) return { problem: 'wrong_session' };
  if (payload.sub !== expected.accountId) return { problem: 'wrong_account' };
  const jti = String(payload.jti ?? '');
  if (!/^[0-9a-f-]{36}$/i.test(jti)) return { problem: 'malformed' };

  // Reserve: exactly one caller moves it issued -> reserved.
  const res = await pool.query(
    `UPDATE owner_verification_tickets SET state = 'reserved', reserved_at = NOW()
      WHERE jti = $1 AND state = 'issued' AND expires_at > NOW() AND session_hash = $2 AND operation_key = $3`,
    [jti, expected.sessionHash, expected.operation],
  );
  if (res.rowCount === 1) return { jti };
  const { rows } = await pool.query<{ state: string }>('SELECT state FROM owner_verification_tickets WHERE jti = $1', [jti]);
  if (!rows[0]) return { problem: 'unknown' };
  return { problem: rows[0].state === 'issued' ? 'expired' : 'used' };
}

/** End of the request that reserved `jti`: a 4xx changed nothing, so the ticket goes back (until it expires); anything else spends it. */
export async function finishTicket(jti: string, statusCode: number): Promise<'consumed' | 'released'> {
  if (statusCode >= 400 && statusCode < 500) {
    await pool.query(`UPDATE owner_verification_tickets SET state = 'issued', reserved_at = NULL WHERE jti = $1 AND state = 'reserved'`, [jti]);
    return 'released';
  }
  await pool.query(`UPDATE owner_verification_tickets SET state = 'consumed', consumed_at = NOW() WHERE jti = $1 AND state = 'reserved'`, [jti]);
  return 'consumed';
}

/** Housekeeping: old challenges and tickets (the audit rows are kept). */
export async function purgeOldOwnerRows(): Promise<void> {
  await pool.query(`DELETE FROM owner_verification_tickets WHERE expires_at < NOW() - INTERVAL '7 days'`);
  await pool.query(`DELETE FROM owner_verification_challenges WHERE expires_at < NOW() - INTERVAL '1 day'`);
}
