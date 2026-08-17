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

const KEYLEN = 64;
const SALT_BYTES = 16;
const BCRYPT_RE = /^\$2[aby]\$/;

export function hashPassword(password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(SALT_BYTES).toString('hex');
    crypto.scrypt(password, salt, KEYLEN, (err, derived) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt}$${derived.toString('hex')}`);
    });
  });
}

export function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  return new Promise((resolve) => {
    if (!stored) return resolve(false);
    if (BCRYPT_RE.test(stored)) {
      bcrypt.compare(password, stored, (err, match) => resolve(!err && match === true));
      return;
    }
    const [scheme, salt, hashHex] = stored.split('$');
    if (scheme !== 'scrypt' || !salt || !hashHex) return resolve(false);
    crypto.scrypt(password, salt, KEYLEN, (err, derived) => {
      if (err) return resolve(false);
      const expected = Buffer.from(hashHex, 'hex');
      // Guard timingSafeEqual against length mismatch.
      if (expected.length !== derived.length) return resolve(false);
      resolve(crypto.timingSafeEqual(expected, derived));
    });
  });
}
