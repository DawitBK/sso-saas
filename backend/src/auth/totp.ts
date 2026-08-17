/**
 * TOTP (RFC 6238) on Node's built-in crypto — no external dependency.
 * SHA-1, 6 digits, 30-second step, ±1 step verification window (clock skew).
 * Compatible with Google Authenticator / Authy / 1Password etc.
 */

import crypto from 'node:crypto';
import { IDP_CONFIG } from '../config.js';

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

/** Decrypt a stored secret. Falls back to returning the input unchanged for any
 *  pre-existing plaintext row (base32 has no `:`), so no backfill migration is
 *  required — it self-heals to encrypted on the next enroll. */
export function decryptTotpSecret(stored: string): string {
  const parts = stored.split(':');
  if (parts.length !== 3) return stored;
  const [ivHex, tagHex, dataHex] = parts;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', TOTP_ENC_KEY, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    return Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]).toString('utf8');
  } catch {
    return stored;
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

/** Verify a 6-digit code against the secret, allowing ±1 time step of skew. */
export function verifyTotp(secret: string, code: string): boolean {
  const normalized = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (const drift of [-1, 0, 1]) {
    const expected = hotp(key, counter + drift);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(normalized))) return true;
  }
  return false;
}

/** otpauth:// URI for authenticator apps (manual-entry key = the secret itself). */
export function otpauthUri(email: string, secret: string): string {
  const issuer = 'Example Corp SSO';
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}
