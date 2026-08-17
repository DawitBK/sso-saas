import { describe, expect, it } from '@jest/globals';
import { issueCsrf as issueInteractionCsrf, validateCsrf as validateInteractionCsrf } from '../src/interactions/csrf.js';
import { issueCsrf as issueAdminCsrf, validateCsrf as validateAdminCsrf } from '../src/admin/csrf.js';
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

    expect(hash).toMatch(/^scrypt\$[0-9a-f]{32}\$[0-9a-f]{128}$/);
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

  it('admin CSRF tokens have an isolated cookie scope', () => {
    const res = responseRecorder();
    const token = issueAdminCsrf(res as any, false);
    const cookie = res.cookies[0];

    expect(cookie.name).toBe('idp_admin_csrf');
    expect(cookie.options.path).toBe('/admin');
    expect(cookie.options.secure).toBe(false);
    expect(validateAdminCsrf({ headers: { cookie: `idp_admin_csrf=${token}` }, body: { csrf: token } } as any)).toBe(true);
  });

  it('TOTP secrets are base32, encrypted at rest, and create a standards URI', () => {
    const secret = generateTotpSecret();
    const encrypted = encryptTotpSecret(secret);

    expect(secret).toMatch(/^[A-Z2-7]+$/);
    expect(encrypted).not.toBe(secret);
    expect(decryptTotpSecret(encrypted)).toBe(secret);
    expect(verifyTotp(secret, 'not-a-code')).toBe(false);
    expect(otpauthUri('admin@examplecorp.com', secret)).toMatch(/^otpauth:\/\/totp\/Example%20Corp%20SSO:admin%40examplecorp\.com\?/);
  });
});
