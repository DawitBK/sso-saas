/**
 * Password hashing for the local user store. New/reset passwords use Node's
 * built-in scrypt (no native build step — robust cross-platform, unlike
 * argon2/bcrypt native). Format stored in `idp_users.password_hash`:
 * `scrypt$<saltHex>$<hashHex>`.
 *
 * verifyPassword() ALSO accepts a real bcrypt hash (`$2a$`/`$2b$`/`$2y$`
 * prefix) so GMS's own legacy-users.json hashes can be copied verbatim into
 * `idp_users.password_hash` (see seed-users.ts) — this lets a mirrored real
 * employee log into SSO with the exact password they already use for GMS,
 * without SSO ever needing (or being able to recover) their plaintext.
 * hashPassword() never produces a bcrypt hash itself; bcrypt only appears
 * here as a read path for pre-existing hashes from another system.
 */

import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import { IDP_CONFIG } from '../config.js';
import { GateBusyError, WorkGate } from '../infrastructure/workGate.js';

/** Every scrypt run goes through this gate (see infrastructure/workGate.ts for why). A refusal is a GateBusyError, which sign-in answers with 503. */
export const passwordGate = new WorkGate(IDP_CONFIG.passwordHash.concurrency, IDP_CONFIG.passwordHash.maxQueue, IDP_CONFIG.passwordHash.maxWaitMs);

function scryptAsync(password: string, salt: string, n: number, r: number, p: number): Promise<Buffer> {
  return passwordGate.run(
    () => new Promise<Buffer>((resolve, reject) => {
      crypto.scrypt(password, salt, KEYLEN, { N: n, r, p, maxmem: maxmemFor(n, r) }, (err, derived) => (err ? reject(err) : resolve(derived)));
    }),
  );
}

const KEYLEN = 64;
const SALT_BYTES = 16;
const BCRYPT_RE = /^\$2[aby]\$/;

/**
 * P2-9 item 7: the cost parameters are now IN the stored string.
 *
 * The old format was `scrypt$<salt>$<hash>` — no N, r or p. Node's scrypt
 * defaults (N=2^14, r=8, p=1) were therefore an implicit, permanent part of every
 * stored hash: raising N would have made every existing password unverifiable,
 * because verifyPassword had no way to know which cost a given row was derived
 * with. A password format you cannot strengthen without a mass reset is a
 * one-way door, and it was already shut.
 *
 * New format: `scrypt$<N>$<r>$<p>$<salt>$<hash>` (6 fields). The 3-field form is
 * still read, at the defaults it was created with, and any password verified
 * against it is transparently re-hashed at the current cost — see
 * needsRehash()/hashPassword() and the caller in auth/local-users.ts. So the
 * migration happens one successful login at a time, with no reset and no
 * flag day.
 *
 * N is raised to 2^17 for new hashes. That is ~8x the work of the old default;
 * scrypt's memory cost scales with N too (128 * N * r bytes ≈ 128 MB at N=2^17,
 * r=8 — sized deliberately, since scrypt's whole point is being memory-hard).
 */
const SCRYPT_N = 1 << 17;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

/** Node's own defaults, which is what a 3-field legacy hash was made with. */
const LEGACY_N = 1 << 14;
const LEGACY_R = 8;
const LEGACY_P = 1;

/**
 * maxmem must be raised explicitly: Node's default cap is 32 MB, and
 * 128 * N * r at N=2^17 exceeds it, so scrypt would throw rather than run.
 */
function maxmemFor(n: number, r: number): number {
  return Math.max(32 * 1024 * 1024, 256 * n * r);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
  const derived = await scryptAsync(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P);
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt}$${derived.toString('hex')}`;
}

/**
 * True when `stored` was produced at a weaker cost than the current one (or in
 * the legacy 3-field format, or by bcrypt from the GMS import). Callers that have
 * just verified a password successfully — and therefore hold the plaintext for
 * one moment — should re-hash and store the result.
 */
export function needsRehash(stored: string | null): boolean {
  if (!stored) return false;
  /**
   * Bcrypt hashes are deliberately EXCLUDED. They are GMS's own hashes, copied
   * verbatim into idp_users so a mirrored employee can sign into SSO with the
   * password they already use for GMS (see this file's header and seed-users.ts).
   * Silently converting them to scrypt would break that documented property —
   * the row would no longer match GMS's, and a re-seed would flip it back —
   * for a marginal strengthening. Their cost is GMS's business, not SSO's.
   */
  if (BCRYPT_RE.test(stored)) return false;
  const parts = stored.split('$');
  if (parts[0] !== 'scrypt') return false;
  if (parts.length === 3) return true; // legacy, no cost parameters
  if (parts.length !== 6) return false;
  return Number(parts[1]) < SCRYPT_N || Number(parts[2]) < SCRYPT_R || Number(parts[3]) < SCRYPT_P;
}

export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  if (!stored) return false;
  if (BCRYPT_RE.test(stored)) {
    return new Promise<boolean>((resolve) => {
      bcrypt.compare(password, stored, (err, match) => resolve(!err && match === true));
    });
  }
  const parts = stored.split('$');
  if (parts[0] !== 'scrypt') return false;

  // Two accepted shapes: the current `scrypt$N$r$p$salt$hash`, and the legacy
  // `scrypt$salt$hash` whose cost was Node's default at the time it was written.
  let n = LEGACY_N;
  let r = LEGACY_R;
  let p = LEGACY_P;
  let salt: string | undefined;
  let hashHex: string | undefined;
  if (parts.length === 6) {
    n = Number(parts[1]);
    r = Number(parts[2]);
    p = Number(parts[3]);
    salt = parts[4];
    hashHex = parts[5];
    if (!Number.isInteger(n) || !Number.isInteger(r) || !Number.isInteger(p) || n < 2 || r < 1 || p < 1) return false;
  } else if (parts.length === 3) {
    salt = parts[1];
    hashHex = parts[2];
  } else {
    return false;
  }
  if (!salt || !hashHex) return false;

  let derived: Buffer;
  try {
    derived = await scryptAsync(password, salt, n, r, p);
  } catch (err) {
    // A refusal because too many checks are already running is NOT a wrong password: it must reach the caller as "busy" (503),
    // never be counted as a failed sign-in or shown as "incorrect password".
    if (err instanceof GateBusyError) throw err;
    return false;
  }
  const expected = Buffer.from(hashHex, 'hex');
  // Guard timingSafeEqual against length mismatch.
  if (expected.length !== derived.length) return false;
  return crypto.timingSafeEqual(expected, derived);
}
