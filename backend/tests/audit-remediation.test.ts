/**
 * Acceptance tests for the platform-audit remediation (P2-1).
 *
 * Scoped deliberately to the pure, dependency-free security primitives the fixes
 * introduced or changed. Everything here runs with no database, no LDAP and no
 * HTTP server, which is why it is worth having: the SSO suite previously had no
 * coverage of any of this, and these are the functions whose failure modes are
 * silent by construction — a replayed TOTP code, a login-CSRF'd flow, a password
 * hash that can never be strengthened.
 *
 * What is NOT covered here, so it is on the record rather than implied:
 *   - the lockout decision (auth/account.ts) needs idp_login_events, so it needs a
 *     database;
 *   - the OIDC leg wiring (portal/bridge/DMS callbacks) needs a live provider;
 *   - the audit chain's truncation detection needs idp_admin_audit and its anchor.
 * Those are integration tests against a real Postgres, which this suite has no
 * harness for yet.
 */

import { describe, expect, it, jest } from '@jest/globals';
import nodeCrypto from 'node:crypto';
import { createFlowBinding, flowBindingMatches, flowBindingCookieOptions } from '../src/auth/flow-binding.js';
import { hashPassword, needsRehash, verifyPassword } from '../src/auth/password.js';
import {
  decryptTotpSecret,
  encryptTotpSecret,
  generateTotpSecret,
  verifyTotp,
  assertTotpEncryptionUsable,
  TotpSecretUndecryptableError,
} from '../src/auth/totp.js';
import { hasLogoutIntent, LOGOUT_INTENT_COOKIE, setLogoutIntent } from '../src/auth/logout-intent.js';

function responseRecorder() {
  const cookies: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
  return {
    cookies,
    cookie(name: string, value: string, options: Record<string, unknown>) {
      cookies.push({ name, value, options });
    },
  };
}

describe('P1-1 — OIDC flow browser-binding', () => {
  it('accepts only the token it issued, and fails closed on everything else', () => {
    const binding = createFlowBinding();

    expect(flowBindingMatches(binding.token, binding.hash)).toBe(true);

    // The attack this exists to stop: an attacker holds a valid code+state pair
    // from their own completed authorization and feeds it to a victim's browser.
    // That browser has no binding cookie for this origin, so it cannot redeem it.
    expect(flowBindingMatches(undefined, binding.hash)).toBe(false);
    expect(flowBindingMatches('', binding.hash)).toBe(false);

    // A different browser's binding must not satisfy this flow.
    expect(flowBindingMatches(createFlowBinding().token, binding.hash)).toBe(false);

    // A pending record written by a build that predates the binding has no hash
    // at all. It must be refused, not waved through.
    expect(flowBindingMatches(binding.token, null)).toBe(false);
    expect(flowBindingMatches(binding.token, undefined)).toBe(false);

    // A stored value that is not 64 hex characters cannot be a SHA-256.
    expect(flowBindingMatches(binding.token, 'deadbeef')).toBe(false);
    expect(flowBindingMatches(binding.token, 'z'.repeat(64))).toBe(false);
  });

  it('never stores the raw token', () => {
    const binding = createFlowBinding();
    expect(binding.hash).not.toBe(binding.token);
    expect(binding.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(binding.token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('scopes the cookie to the callback path and keeps it httpOnly and lax', () => {
    const options = flowBindingCookieOptions('/sso/portal/callback', 600_000, true);
    expect(options.httpOnly).toBe(true);
    expect(options.path).toBe('/sso/portal/callback');
    expect(options.secure).toBe(true);
    // 'strict' would withhold the cookie on the top-level cross-site redirect
    // back from the IdP and break every login — this is load-bearing, not taste.
    expect(options.sameSite).toBe('lax');
    expect(flowBindingCookieOptions('/x', 1, false).secure).toBe(false);
  });
});

describe('P1-4 — TOTP replay and key-mismatch handling', () => {
  /**
   * Independent HOTP, so this test is a real check rather than a restatement of
   * the implementation. RFC 4226: HMAC-SHA1 over the big-endian counter, dynamic
   * truncation, modulo 10^6.
   */
  function independentHotp(base32Secret: string, counter: number): string {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    const bytes: number[] = [];
    for (const ch of base32Secret.toUpperCase().replace(/[^A-Z2-7]/g, '')) {
      value = (value << 5) | alphabet.indexOf(ch);
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    const hmac = nodeCrypto.createHmac('sha1', Buffer.from(bytes)).update(counterBuf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const code =
      ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
    return String(code % 1_000_000).padStart(6, '0');
  }

  it('returns the matched counter, which is what makes a replay detectable', () => {
    const secret = generateTotpSecret();
    const step = Math.floor(Date.now() / 1000 / 30);
    const liveCode = independentHotp(secret, step);

    const matched = verifyTotp(secret, liveCode);
    expect(matched).toBe(step);

    // The same code verifies again — it is cryptographically valid for up to 90
    // seconds thanks to the ±1 drift window. That is exactly why a boolean return
    // could not stop a replay, and why the caller compares the counter against
    // the account's stored totp_last_counter.
    expect(verifyTotp(secret, liveCode)).toBe(step);

    // The caller's rule, stated explicitly: once `step` is burned, a code that
    // matches `step` (or anything earlier) must be refused.
    const lastCounter = step;
    expect(matched !== null && matched <= lastCounter).toBe(true);

    // A code from the NEXT step is still accepted, so a legitimate second login
    // moments later is not broken by the replay guard.
    const nextCode = independentHotp(secret, step + 1);
    const nextMatched = verifyTotp(secret, nextCode);
    expect(nextMatched).toBe(step + 1);
    expect(nextMatched !== null && nextMatched <= lastCounter).toBe(false);
  });

  it('accepts codes one step either side of now, and rejects malformed input', () => {
    const secret = generateTotpSecret();
    const step = Math.floor(Date.now() / 1000 / 30);

    expect(verifyTotp(secret, independentHotp(secret, step - 1))).toBe(step - 1);
    expect(verifyTotp(secret, independentHotp(secret, step + 1))).toBe(step + 1);
    // Two steps out is outside the window.
    expect(verifyTotp(secret, independentHotp(secret, step + 2))).toBeNull();

    expect(verifyTotp(secret, 'nope')).toBeNull();
    expect(verifyTotp(secret, '12345')).toBeNull();
    expect(verifyTotp(secret, '1234567')).toBeNull();
  });

  it('round-trips an encrypted secret and passes the boot self-test', () => {
    const secret = generateTotpSecret();
    const encrypted = encryptTotpSecret(secret);
    expect(encrypted).not.toBe(secret);
    expect(decryptTotpSecret(encrypted)).toBe(secret);
    expect(() => assertTotpEncryptionUsable()).not.toThrow();
  });

  it('returns a legacy plaintext secret unchanged (base32 has no colon)', () => {
    const legacy = generateTotpSecret();
    expect(decryptTotpSecret(legacy)).toBe(legacy);
  });

  it('THROWS on a secret it cannot decrypt, instead of handing back ciphertext', () => {
    // This is the whole point of the fix. The old code did `catch { return stored; }`,
    // so a key change made getTotpState report every enrolled user as having a
    // "secret" that was really ciphertext — base32Decode stripped it into a
    // garbage key, every code failed, and five attempts later the account locked.
    // Silently, for every MFA user at once.
    const encrypted = encryptTotpSecret(generateTotpSecret());
    const [iv, tag, data] = encrypted.split(':');
    // Corrupt the ciphertext, keeping the 3-part shape: this is indistinguishable
    // from a value encrypted under a different TOTP_ENCRYPTION_KEY.
    const corrupted = `${iv}:${tag}:${data.slice(0, -2)}${data.slice(-2) === 'ff' ? '00' : 'ff'}`;

    const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      expect(() => decryptTotpSecret(corrupted)).toThrow(TotpSecretUndecryptableError);
    } finally {
      consoleSpy.mockRestore();
    }
  });
});

describe('P1-5 — logout intent marker', () => {
  it('sets an httpOnly cookie scoped to the end-session path', () => {
    const res = responseRecorder();
    setLogoutIntent(res as never);

    expect(res.cookies).toHaveLength(1);
    const cookie = res.cookies[0];
    expect(cookie.name).toBe(LOGOUT_INTENT_COOKIE);
    expect(cookie.options.httpOnly).toBe(true);
    expect(cookie.options.sameSite).toBe('lax');
    expect(String(cookie.options.path)).toMatch(/\/session$/);
    // Short-lived: a stale marker must not sit in the jar waiting to be used by a
    // later cross-site request.
    expect(cookie.options.maxAge).toBe(60_000);
    expect(hasLogoutIntent(cookie.value)).toBe(true);
  });

  it('rejects anything it did not issue, so /session/end shows a real confirmation', () => {
    // A third-party page cannot set a cookie on this origin, which is what makes
    // presence sufficient proof. These are the shapes that must not pass.
    expect(hasLogoutIntent(undefined)).toBe(false);
    expect(hasLogoutIntent('')).toBe(false);
    expect(hasLogoutIntent('yes')).toBe(false);
    expect(hasLogoutIntent('g'.repeat(48))).toBe(false); // right length, not hex
    expect(hasLogoutIntent('ab'.repeat(4))).toBe(false); // hex, wrong length
  });
});

describe('P2-9 item 7 — scrypt cost parameters are stored, and upgrade on login', () => {
  it('writes the cost into the hash and still verifies', async () => {
    const hash = await hashPassword('correct horse battery staple');
    expect(hash).toMatch(/^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong password', hash)).toBe(false);
    expect(needsRehash(hash)).toBe(false);
  });

  it('still verifies a legacy 3-field hash, and flags it for rehash', async () => {
    // What every existing row looks like. It has no cost parameters, so it must
    // be verified at Node's defaults — and then upgraded, one login at a time,
    // rather than invalidated en masse.
    const crypto = await import('node:crypto');
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync('legacy secret', salt, 64).toString('hex');
    const legacy = `scrypt$${salt}$${derived}`;

    expect(await verifyPassword('legacy secret', legacy)).toBe(true);
    expect(await verifyPassword('not it', legacy)).toBe(false);
    expect(needsRehash(legacy)).toBe(true);
  });

  it('leaves an imported bcrypt hash alone', async () => {
    // GMS's own hashes are copied verbatim into idp_users so a mirrored employee
    // can sign in with the password they already use. Converting them to scrypt
    // would break that documented property for a marginal gain.
    const bcrypt = (await import('bcryptjs')).default;
    const imported = await bcrypt.hash('shared with gms', 10);
    expect(await verifyPassword('shared with gms', imported)).toBe(true);
    expect(needsRehash(imported)).toBe(false);
  });

  it('rejects malformed stored values rather than throwing', async () => {
    expect(await verifyPassword('x', 'not-a-password-hash')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$only$three$four')).toBe(false);
    expect(await verifyPassword('x', 'scrypt$abc$8$1$deadbeef$cafe')).toBe(false);
    expect(await verifyPassword('x', null)).toBe(false);
    expect(needsRehash(null)).toBe(false);
  });
});
