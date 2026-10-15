/**
 * TOTP (RFC 6238) on Node's built-in crypto — no external dependency.
 * SHA-1, 6 digits, 30-second step, ±1 step verification window (clock skew).
 * Compatible with Google Authenticator / Authy / 1Password etc.
 */

import crypto from 'node:crypto';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';

const B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP_SECONDS = 30;
const DIGITS = 6;

// Derived via sha256 so any configured key length works for AES-256.
const TOTP_ENC_KEY = crypto.createHash('sha256').update(IDP_CONFIG.totpEncryptionKey).digest();

/**
 * Encrypt a TOTP secret for storage (AES-256-GCM, random IV per call) — was
 * stored as plain TEXT, so a DB backup leak or read-only replica handed out
 * live 2FA seeds for every enrolled user.
 */
export function encryptTotpSecret(secret: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', TOTP_ENC_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return `${iv.toString('hex')}:${cipher.getAuthTag().toString('hex')}:${ciphertext.toString('hex')}`;
}

/**
 * Raised when a value that IS encrypted (3 colon-separated parts) cannot be
 * decrypted with the configured key — i.e. TOTP_ENCRYPTION_KEY changed, or the
 * row was written by a different deployment.
 */
export class TotpSecretUndecryptableError extends Error {
  constructor() {
    super('TOTP secret could not be decrypted with the configured TOTP_ENCRYPTION_KEY');
    this.name = 'TotpSecretUndecryptableError';
  }
}

/** Process-lifetime counter, surfaced on /metrics as users_mfa_secret_undecryptable. */
let undecryptableSecrets = 0;
export function undecryptableSecretCount(): number {
  return undecryptableSecrets;
}

/**
 * Decrypt a stored secret.
 *
 * Two failure modes that used to be collapsed into one, disastrously:
 *
 *  - `parts.length !== 3` is a legacy PLAINTEXT row (base32 has no `:`), written
 *    before secrets were encrypted. Returning it unchanged is correct and is why
 *    no backfill migration was needed — it self-heals to encrypted on next enroll.
 *
 *  - A 3-part value that FAILS to decrypt is a key mismatch, and the old
 *    `catch { return stored; }` handed the raw ciphertext back to the caller. It
 *    is a non-empty string, so `getTotpState` reported the user as enrolled with
 *    a "secret", the MFA prompt rendered, `base32Decode` silently stripped every
 *    non-base32 character out of the hex/colon soup into a garbage HMAC key,
 *    every code the user typed failed, and after five attempts the account
 *    locked. Silently. For every enrolled user at once, with no log line, no
 *    metric, and an error indistinguishable from "you typed it wrong".
 *    Rotating TOTP_ENCRYPTION_KEY was therefore a platform-wide MFA outage that
 *    looked like a user problem. Now it throws, counts, and logs.
 */
export function decryptTotpSecret(stored: string): string {
  const parts = stored.split(':');
  if (parts.length !== 3) return stored;
  const [ivHex, tagHex, dataHex] = parts;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', TOTP_ENC_KEY, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  } catch (err) {
    undecryptableSecrets += 1;
    logger.error(
      { err, undecryptableSecrets },
      '[idp:totp:ALERT] a stored TOTP secret could not be decrypted — TOTP_ENCRYPTION_KEY does not match the key it was encrypted with. Every enrolled user is affected and cannot complete MFA. Restore the previous key or re-enroll users; do NOT let them burn through attempts and lock themselves out.',
    );
    throw new TotpSecretUndecryptableError();
  }
}

/**
 * Boot-time round-trip check on the configured key. A wrong TOTP_ENCRYPTION_KEY
 * is not detectable by encrypting alone (any key encrypts fine) — this only
 * catches a key that cannot even encrypt/decrypt its own output, e.g. an unset
 * or truncated value in an environment where the derivation changes. It is the
 * cheap half of the guard; decryptTotpSecret above is what catches the real
 * "key changed since the rows were written" case, per row, loudly.
 */
export function assertTotpEncryptionUsable(): void {
  const probe = 'JBSWY3DPEHPK3PXP';
  const roundTripped = decryptTotpSecret(encryptTotpSecret(probe));
  if (roundTripped !== probe) {
    throw new Error(
      'TOTP encryption self-test failed: a secret encrypted and immediately decrypted with the configured TOTP_ENCRYPTION_KEY did not round-trip. Refusing to start — every MFA login would fail.',
    );
  }
}

export function generateTotpSecret(): string {
  const bytes = crypto.randomBytes(20); // 160-bit, RFC 4226 recommended
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(secret: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 10 ** DIGITS).padStart(DIGITS, '0');
}

/**
 * Verify a 6-digit code against the secret, allowing ±1 time step of skew.
 *
 * Returns the MATCHED time-step counter, or null if no step in the window
 * matches. It used to return a bare boolean, which made replay protection
 * impossible: the ±1 window means a single observed code is valid for up to 90
 * seconds, and with no record of which counter was consumed the same code could
 * be submitted repeatedly inside that window. Callers must compare the returned
 * counter against the account's stored `totp_last_counter` and reject anything
 * at or below it — see recordMfaAttempt() in local-users.ts, which persists the
 * new high-water mark in the same statement that clears the failure counter.
 *
 * Iterates the whole window even after a match so the work done is independent
 * of WHICH step matched.
 */
export function verifyTotp(secret: string, code: string): number | null {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return null;
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  let matched: number | null = null;
  for (const drift of [-1, 0, 1]) {
    const step = counter + drift;
    const expected = hotp(key, step);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(normalized)) && matched === null) {
      matched = step;
    }
  }
  return matched;
}

/** otpauth:// URI for authenticator apps (manual-entry key = the secret itself). */
export function otpauthUri(email: string, secret: string): string {
  const issuer = 'Example Corp SSO';
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}
