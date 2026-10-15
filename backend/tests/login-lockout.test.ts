/**
 * Password lockout (auth/account.ts evaluateLockout + auth/local-users.ts authenticateLocal).
 * Owner decision 2026-10-09: no lockout by default (LOGIN_LOCKOUT_ENABLED=false); when it is on,
 * a password reset must wipe the failed-attempt window so the new password works at once.
 */

const mockQuery = jest.fn();
const cfg = { loginLockoutEnabled: false, platformAdminPepper: '', totpEncryptionKey: 'unit-test-key', passwordHash: { concurrency: 3, maxQueue: 60, maxWaitMs: 8000 } };
jest.mock('../src/db/pool.js', () => ({ pool: { query: (...a: unknown[]) => mockQuery(...a), connect: jest.fn() } }));
jest.mock('../src/config.js', () => ({ IDP_CONFIG: cfg, AD_GROUPS_CLAIM: 'ad_groups' }));
jest.mock('../src/auth/ldap.service.js', () => ({ isAdEnabled: () => false, authenticateAD: jest.fn() }));
jest.mock('../src/auth/platform-admin.js', () => ({ findPlatformAdminForLogin: async () => null }));
jest.mock('../src/auth/client-role-claims.js', () => ({ EDAMS_ROLES_CLAIM: 'e', GMS_ROLES_CLAIM: 'g', resolveClientRoleClaims: async () => ({}) }));
jest.mock('../src/auth/revoke.js', () => ({ revokeAllSessions: jest.fn() }));
jest.mock('../src/logging/logger.js', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() } }));

import { hashPassword } from '../src/auth/password.js';
import { authenticateUser } from '../src/auth/account.js';

let hash: string;
const FAILURES = { email_failures: '9', distinct_ips: '1', pair_failures: '9', ip_failures: '9' };

function row(over: Record<string, unknown> = {}) {
  return {
    id: 'u1', email: 'a@b.co', email_verified: true, given_name: 'A', family_name: 'B', password_hash: hash,
    is_active: true, must_change_password: false, failed_logins: 0, locked_until: null, login_failures_cleared_at: null, ...over,
  };
}

function wire(userRow: Record<string, unknown>) {
  mockQuery.mockImplementation(async (sql: string) => {
    if (/FROM idp_login_events/.test(sql)) return { rows: [FAILURES] };
    if (/SELECT login_failures_cleared_at/.test(sql)) return { rows: [{ login_failures_cleared_at: userRow.login_failures_cleared_at }] };
    if (/FROM idp_users WHERE lower\(btrim\(email\)\)/.test(sql)) return { rows: [userRow] };
    if (/FROM idp_user_groups/.test(sql)) return { rows: [] };
    return { rows: [], rowCount: 1 };
  });
}

beforeAll(async () => { hash = await hashPassword('Correct-Pass-1'); }, 30_000);
beforeEach(() => { mockQuery.mockReset(); cfg.loginLockoutEnabled = false; });

describe('lockout switched off (default)', () => {
  it('accepts the right password even with many recent failures and a stale lock on the row', async () => {
    wire(row({ failed_logins: 12, locked_until: new Date(Date.now() + 10 * 60_000) }));
    const r = await authenticateUser('A@B.co ', 'Correct-Pass-1', '10.0.0.1');
    expect(r.ok).toBe(true);
  });

  it('a wrong password is "invalid_credentials" every time and never sets locked_until', async () => {
    wire(row({ failed_logins: 40 }));
    const r = await authenticateUser('a@b.co', 'nope', '10.0.0.1');
    expect(r).toEqual({ ok: false, reason: 'invalid_credentials' });
    const update = mockQuery.mock.calls.find((c) => /SET failed_logins = \$2, locked_until = \$3/.test(String(c[0])));
    expect(update).toBeDefined();
    expect(update![1][2]).toBeNull();
  });
});

describe('lockout switched on', () => {
  beforeEach(() => { cfg.loginLockoutEnabled = true; });

  it('refuses while 5+ failures sit in the window', async () => {
    wire(row());
    expect(await authenticateUser('a@b.co', 'Correct-Pass-1', '10.0.0.1')).toEqual({ ok: false, reason: 'locked' });
  });

  it('counts only failures AFTER the account\'s last reset: the cleared-at time is passed to the window query', async () => {
    const cleared = new Date();
    wire(row({ login_failures_cleared_at: cleared }));
    await authenticateUser('a@b.co', 'x', '10.0.0.1');
    const q = mockQuery.mock.calls.find((c) => /FROM idp_login_events/.test(String(c[0])));
    expect(q![1][2]).toBe(cleared);
    expect(String(q![0])).toMatch(/created_at > \$3/);
  });
});
