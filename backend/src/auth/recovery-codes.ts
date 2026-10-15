/**
 * Two-factor recovery codes: ten single-use codes that stand in for the authenticator app when the phone is lost.
 *
 * Shape: 10 characters from a 31-letter alphabet without look-alikes (no 0/o, 1/l/i), shown as `abcde-fghjk`, about 49 bits each.
 * That is plenty because (a) a code is only ever tried after the password, behind the same five-attempts lockout as an authenticator
 * code, and (b) the table holds only an HMAC keyed from TOTP_ENCRYPTION_KEY, so a stolen copy of the table cannot be ground down
 * offline the way a plain SHA-256 of a 49-bit value could.
 *
 * Accepting one is a single `UPDATE ... WHERE used_at IS NULL RETURNING`: two requests racing with the same code cannot both win.
 */
import crypto from 'node:crypto';
import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';

export const RECOVERY_CODE_COUNT = 10;
const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';
const LENGTH = 10;

const key = (): Buffer => crypto.createHash('sha256').update(`recovery-codes:${IDP_CONFIG.totpEncryptionKey}`).digest();

/** One fresh code, `xxxxx-xxxxx`. randomInt is unbiased (no modulo skew toward the first letters). */
export function generateRecoveryCode(): string {
  let raw = '';
  for (let i = 0; i < LENGTH; i += 1) raw += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

/** What a person typed, reduced to the 10 characters, or null when it cannot be a recovery code (so a mistyped 6-digit code never costs a query). */
export function normalizeRecoveryCode(input: string): string | null {
  const raw = input.toLowerCase().replace(/[\s-]/g, '');
  if (raw.length !== LENGTH) return null;
  for (const ch of raw) if (!ALPHABET.includes(ch)) return null;
  return raw;
}

export function hashRecoveryCode(normalized: string): string {
  return crypto.createHmac('sha256', key()).update(normalized).digest('hex');
}

/** True when the text is the shape of an authenticator code (six digits, spaces allowed) rather than a recovery code. */
export function looksLikeTotp(input: string): boolean {
  return /^\d{6}$/.test(input.replace(/\s/g, ''));
}

/** Replace every code the person has with a fresh set and return the plaintext ONCE. The old set stops working in the same transaction. */
export async function replaceRecoveryCodes(userId: string): Promise<string[]> {
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, generateRecoveryCode);
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    await db.query('DELETE FROM idp_recovery_codes WHERE user_id = $1', [userId]);
    for (const code of codes) {
      await db.query('INSERT INTO idp_recovery_codes (user_id, code_hash) VALUES ($1, $2)', [userId, hashRecoveryCode(normalizeRecoveryCode(code) as string)]);
    }
    await db.query('COMMIT');
    return codes;
  } catch (err) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    db.release();
  }
}

/** Spend a code. True only for the first valid use. */
export async function consumeRecoveryCode(userId: string, input: string): Promise<boolean> {
  const normalized = normalizeRecoveryCode(input);
  if (!normalized) return false;
  const { rowCount } = await pool.query(
    'UPDATE idp_recovery_codes SET used_at = NOW() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL',
    [userId, hashRecoveryCode(normalized)],
  );
  return (rowCount ?? 0) > 0;
}

export async function recoveryCodesRemaining(userId: string): Promise<number> {
  const { rows } = await pool.query<{ n: string }>('SELECT COUNT(*) AS n FROM idp_recovery_codes WHERE user_id = $1 AND used_at IS NULL', [userId]);
  return Number(rows[0]?.n ?? 0);
}

export async function clearRecoveryCodes(userId: string): Promise<void> {
  await pool.query('DELETE FROM idp_recovery_codes WHERE user_id = $1', [userId]);
}
