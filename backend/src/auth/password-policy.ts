/**
 * What a NEW password must satisfy. One place, used by every route that sets a password (admin create and reset, the
 * forced change at sign-in, the self-service change), so the rules cannot drift apart.
 *
 * Lockout is off by owner decision (2026-10-09), so guessing is bounded only by rate limits; the best remaining defence is
 * refusing the passwords an attacker tries first.
 */
import { getBool, getNumber } from '../settings/store.js';

const COMMON = new Set([
  'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd', '12345678', '123456789', '1234567890', '11111111', '00000000',
  'qwertyui', 'qwerty123', 'qwertyuiop', 'abc12345', 'abcd1234', 'iloveyou', 'admin123', 'administrator', 'welcome1', 'welcome123',
  'letmein1', 'letmein123', 'changeme', 'changeme1', 'examplecorp', 'examplecorp1', 'examplecorp123', 'examplecorp@123',
]);

/** The longest password accepted (a bound on hashing work, and what the forms' inputs stop at). */
export const PASSWORD_MAX_LENGTH = 200;

/** Returns a message when the password is not acceptable, else null. The length and the common-password rule are platform settings (settings/registry.ts). */
export function newPasswordProblem(password: string, email?: string): string | null {
  const minLength = getNumber('password.minLength');
  if (password.length < minLength) return `Password must be at least ${minLength} characters.`;
  if (password.length > PASSWORD_MAX_LENGTH) return `Password can be at most ${PASSWORD_MAX_LENGTH} characters.`;
  if (!getBool('password.blockCommon')) return null;
  const lower = password.toLowerCase();
  if (COMMON.has(lower)) return 'That password is too common - choose something that is not on every guess list.';
  if (/^(.)\1+$/.test(password)) return 'Password cannot be one repeated character.';
  const local = (email ?? '').split('@')[0]?.toLowerCase();
  if (local && local.length >= 4 && lower.includes(local)) return 'Password must not contain the sign-in name.';
  return null;
}
