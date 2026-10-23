/**
 * Offline recovery codes: printed ONCE at enrolment, kept on paper by the owner, each usable once, and the replacement for the emailed code when
 * the email factor is unavailable (SMTP removed, changed or unreachable). They never replace the security questions or the authenticator.
 *
 * 20 characters from a 32-letter alphabet without look-alikes = 100 bits, so a keyed fast hash (HMAC with the store key) is enough: there is nothing
 * to brute-force. Only the HMACs are stored (inside the sealed store); which ones have been used is a plain table of ids.
 */
import crypto from 'node:crypto';
import { RECOVERY_CODE_COUNT } from './policy.js';
import { keyedHash, safeEqual, type StoreKeys } from './seal.js';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/** `XXXXX-XXXXX-XXXXX-XXXXX` */
export function newRecoveryCode(): string {
  const bytes = crypto.randomBytes(20);
  let out = '';
  for (let i = 0; i < 20; i += 1) {
    out += ALPHABET[(bytes[i] as number) % 32];
    if (i % 5 === 4 && i < 19) out += '-';
  }
  return out;
}

/** Upper-case and drop everything that is not a letter or digit, so spaces, dashes and case do not matter when typing one in. */
export function normaliseRecoveryCode(raw: string): string {
  return String(raw).toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export interface RecoveryRecord {
  id: string;
  mac: string;
}

/** Fresh codes and the records to seal. The plain codes are returned for ONE display and must not be kept. */
export function generateRecoveryCodes(keys: StoreKeys, count = RECOVERY_CODE_COUNT): { codes: string[]; records: RecoveryRecord[] } {
  const codes: string[] = [];
  const records: RecoveryRecord[] = [];
  for (let i = 0; i < count; i += 1) {
    const code = newRecoveryCode();
    codes.push(code);
    records.push({ id: crypto.randomBytes(8).toString('hex'), mac: keyedHash(keys, 'recovery', normaliseRecoveryCode(code)) });
  }
  return { codes, records };
}

/** The id of the record `code` matches, or null. Compares against every record so the time does not say which one (or whether one) matched. */
export function matchRecoveryCode(keys: StoreKeys, records: readonly RecoveryRecord[], code: string): string | null {
  const normalised = normaliseRecoveryCode(code);
  if (normalised.length !== 20) return null;
  const mac = keyedHash(keys, 'recovery', normalised);
  let found: string | null = null;
  for (const r of records) if (safeEqual(mac, r.mac) && found === null) found = r.id;
  return found;
}
