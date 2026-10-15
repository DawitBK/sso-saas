import { describe, expect, it } from '@jest/globals';
import { issueCsrf as issueInteractionCsrf, validateCsrf as validateInteractionCsrf } from '../src/interactions/csrf.js';
import { hashPassword, verifyPassword } from '../src/auth/password.js';
import { decryptTotpSecret, encryptTotpSecret, generateTotpSecret, otpauthUri, verifyTotp } from '../src/auth/totp.js';

function responseRecorder() {
  const cookies: Array<{ name: string; value: string; options: Record<string, unknown> }> = [];
  return {
    cookies,
    cookie(name: string, value: string, options: Record<string, unknown>) {
      cookies.push({ name, value, options });
    },
  };
}

describe('security primitives', () => {
  it('local passwords are salted, verifiable, and reject malformed hashes', async () => {
    const hash = await hashPassword('correct horse battery staple');

    // P2-9 item 7: the format is now scrypt$N$r$p$salt$hash. The cost parameters
    // are IN the string so N can be raised later without invalidating every
    // existing hash — which the old 3-field format made impossible.
    expect(hash).toMatch(/^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
    expect(await verifyPassword('correct horse battery staple', hash)).toBe(true);
    expect(await verifyPassword('wrong password', hash)).toBe(false);
    expect(await verifyPassword('correct horse battery staple', 'not-a-password-hash')).toBe(false);
  });

  it('interaction CSRF tokens are scoped and reject mismatched submissions', () => {
    const res = responseRecorder();
    const token = issueInteractionCsrf(res as any, true);
    const cookie = res.cookies[0];

    expect(cookie.name).toBe('idp_csrf');
    expect(cookie.options.path).toBe('/interaction');
    expect(cookie.options.secure).toBe(true);
    expect(validateInteractionCsrf({ headers: { cookie: `idp_csrf=${token}` }, body: { csrf: token } } as any)).toBe(true);
    expect(validateInteractionCsrf({ headers: { cookie: `idp_csrf=${token}` }, body: { csrf: 'different' } } as any)).toBe(false);
  });

  it('TOTP secrets are base32, encrypted at rest, and create a standards URI', () => {
    const secret = generateTotpSecret();
    const encrypted = encryptTotpSecret(secret);

    expect(secret).toMatch(/^[A-Z2-7]+$/);
    expect(encrypted).not.toBe(secret);
    expect(decryptTotpSecret(encrypted)).toBe(secret);
    // P1-4: verifyTotp returns the MATCHED time-step counter (or null), not a
    // boolean — the caller needs the counter to reject a replayed code.
    expect(verifyTotp(secret, 'not-a-code')).toBeNull();
    expect(otpauthUri('admin@examplecorp.com', secret)).toMatch(/^otpauth:\/\/totp\/Example%20Corp%20SSO:admin%40examplecorp\.com\?/);
  });
});
