/**
 * The Next console's JSON API (api/v1/admin.router.ts), driven over real HTTP against the dev
 * `idp` database with scratch rows (removed in afterAll). Admin authentication, the audit
 * writer, session revocation, DMS and the role catalogue are mocked; everything else is real.
 *
 * Covers the 2026-10-04 discrepancy fixes: group App access / GMS role sign members out only when
 * something changed; an administrator cannot disable their own account; Reset password is refused
 * for an Active Directory account; a created user must change the password at first sign-in;
 * the Sessions list shows the sign-in address; the Sign-ins date filter; the Keys page is the
 * platform administrator's alone.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';

const mockRevoke = jest.fn();
const mockSession: { value: { accountId: string; name: string; email: string; groups: string[]; createdAt: number } } = {
  value: { accountId: '', name: 'Jest Admin', email: 'jest-admin-v1@example.invalid', groups: [], createdAt: 0 },
};

jest.mock('../src/admin/requireAdmin.js', () => {
  const gate = () => (req: { adminSession?: unknown }, _res: unknown, next: () => void) => {
    req.adminSession = mockSession.value;
    next();
  };
  return { requireAdminJson: gate, getPortalSessionFromRequest: jest.fn() };
});
jest.mock('../src/auth/revoke.js', () => ({
  ...jest.requireActual('../src/auth/revoke.js'),
  revokeAllSessions: (...a: unknown[]) => mockRevoke(...a),
}));
jest.mock('../src/admin/audit.js', () => ({
  writeAudit: jest.fn(async () => undefined),
  recentAudit: jest.fn(),
  countAuditRows: jest.fn(),
  verifyAuditChain: jest.fn(),
}));
jest.mock('../src/admin/client-roles.js', () => ({
  ...jest.requireActual('../src/admin/client-roles.js'),
  listDmsRoleNames: async () => ['APPROVER'],
  listGmsRoleNames: async () => ['host'],
  listGmsOfficeScopedRoleNames: async () => [],
}));
jest.mock('../src/admin/dms-internal-client.js', () => {
  class DmsInternalApiError extends Error {
    status = 502;
    code = 'ERR-DMS';
  }
  return {
    DmsInternalApiError,
    getDmsRoleMapping: jest.fn(),
    putDmsRoleMapping: jest.fn(),
    listDmsRoles: jest.fn(),
    getDmsRolePermissions: jest.fn(),
    putDmsRolePermissions: jest.fn(),
    getDmsUserOverrides: jest.fn(),
    putDmsUserOverrides: jest.fn(),
    listDmsMappedGroups: jest.fn(async () => []),
    getDmsUserStatusByEmail: jest.fn(),
    listDmsDepartments: jest.fn(),
    putDmsUserDepartments: jest.fn(),
    listDmsGroupsForRole: jest.fn(),
  };
});

import express from 'express';
import { pool } from '../src/db/pool.js';
import { adminApiRouter, ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { replaceGroupEntitlements, replaceGroupGmsRole } from '../src/admin/access.js';

const TAG = 'jest-v1-actions';
const email = (n: string) => `${TAG}-${n}@example.invalid`;
const GROUP = `CN=${TAG}-group,OU=Groups,DC=example,DC=invalid`;
const CSRF = 'csrf-token-for-jest';

let server: http.Server;
let base = '';
const ids: Record<string, string> = {};

async function call(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', cookie: `${ADMIN_API_CSRF_COOKIE}=${CSRF}` },
    body: method === 'POST' ? JSON.stringify({ ...(body ?? {}), csrf: CSRF }) : undefined,
  });
  return { status: res.status, json: (await res.json()) as any };
}

async function mkUser(name: string, source: 'local' | 'ad', hash: string | null = 'old-hash') {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active)
     VALUES ($1, TRUE, 'Jest', $2, $3, $4, TRUE) RETURNING id`,
    [email(name), name, hash, source],
  );
  ids[name] = rows[0].id;
  return rows[0].id;
}

async function cleanup() {
  const like = `${TAG}-%`;
  await pool.query('DELETE FROM idp_login_events WHERE email LIKE $1', [like]);
  await pool.query(`DELETE FROM oidc_artifacts WHERE id LIKE '${TAG}-%'`);
  await pool.query('DELETE FROM idp_app_entitlements WHERE group_dn = $1', [GROUP]);
  await pool.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [GROUP]);
  await pool.query('DELETE FROM idp_user_groups WHERE group_dn = $1', [GROUP]);
  await pool.query(`DELETE FROM idp_user_groups WHERE user_id IN (SELECT id FROM idp_users WHERE email LIKE $1)`, [like]);
  await pool.query('DELETE FROM idp_users WHERE email LIKE $1', [like]);
}

beforeAll(async () => {
  await cleanup();
  await mkUser('admin', 'local');
  await mkUser('member', 'local');
  await mkUser('adacct', 'ad', null);
  await mkUser('localacct', 'local');
  await pool.query('INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2)', [ids.member, GROUP]);
  mockSession.value.accountId = ids.admin;
  const app = express();
  app.use(express.json());
  app.use('/api/v1/admin', adminApiRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1/admin`;
});

beforeEach(() => {
  mockRevoke.mockReset();
  mockRevoke.mockResolvedValue({ oidcArtifacts: 1, portalSessions: 0, gatewaySessions: 0, pendingLogins: 0, gmsSessions: 0, dmsNotified: true });
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await cleanup();
  await pool.end();
});

describe('group App access and GMS role sign members out only on a real change', () => {
  it('entitlements: a changed set revokes every member, an identical re-save does not', async () => {
    const first = await call('POST', '/groups/entitlements', { dn: GROUP, rp: ['edams'] });
    expect(first.status).toBe(200);
    expect(mockRevoke).toHaveBeenCalledTimes(1);
    expect(mockRevoke.mock.calls[0][0]).toBe(ids.member);

    mockRevoke.mockClear();
    await call('POST', '/groups/entitlements', { dn: GROUP, rp: ['edams'] });
    expect(mockRevoke).not.toHaveBeenCalled();

    // removing an entitlement is a change too (the dangerous direction)
    await call('POST', '/groups/entitlements', { dn: GROUP, rp: [] });
    expect(mockRevoke).toHaveBeenCalledTimes(1);
    const { rowCount } = await pool.query('SELECT 1 FROM idp_app_entitlements WHERE group_dn = $1', [GROUP]);
    expect(rowCount).toBe(0);
  });

  it('entitlements: unknown apps are dropped, and only a real difference counts', async () => {
    const r = await replaceGroupEntitlements(GROUP, ['edams', 'nonsense', 'edams']);
    expect(r).toEqual({ apps: ['edams'], changed: true });
    expect(await replaceGroupEntitlements(GROUP, ['edams', 'nonsense'])).toEqual({ apps: ['edams'], changed: false });
    await replaceGroupEntitlements(GROUP, []);
  });

  it('GMS role: set, same value, change and clear', async () => {
    expect((await call('POST', '/groups/gms-role', { dn: GROUP, role: 'host' })).status).toBe(200);
    expect(mockRevoke).toHaveBeenCalledTimes(1);
    mockRevoke.mockClear();
    await call('POST', '/groups/gms-role', { dn: GROUP, role: 'host' });
    expect(mockRevoke).not.toHaveBeenCalled();
    await call('POST', '/groups/gms-role', { dn: GROUP, role: '' });
    expect(mockRevoke).toHaveBeenCalledTimes(1);
    expect(await replaceGroupGmsRole(GROUP, '')).toEqual({ changed: false });
  });
});

describe('disable and password reset guards', () => {
  it('an administrator cannot disable their own account', async () => {
    const r = await call('POST', `/users/${ids.admin}/toggle-active`);
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('ERR-SELF-SERVICE');
    const { rows } = await pool.query('SELECT is_active FROM idp_users WHERE id = $1', [ids.admin]);
    expect(rows[0].is_active).toBe(true);
    expect(mockRevoke).not.toHaveBeenCalled();
  });

  it('disabling someone else works, and warns when DMS did not confirm', async () => {
    mockRevoke.mockResolvedValue({ oidcArtifacts: 1, portalSessions: 0, gatewaySessions: 0, pendingLogins: 0, gmsSessions: 'failed', dmsNotified: false });
    const r = await call('POST', `/users/${ids.localacct}/toggle-active`);
    expect(r.status).toBe(200);
    expect(r.json.data.isActive).toBe(false);
    expect(r.json.data.warning).toMatch(/GMS could not be reached/);
    expect(r.json.data.warning).toMatch(/DMS did not confirm/);
    // re-enable: no warning
    const back = await call('POST', `/users/${ids.localacct}/toggle-active`);
    expect(back.json.data.isActive).toBe(true);
    expect(back.json.data.warning).toBeUndefined();
  });

  it('a clean disable carries no warning', async () => {
    const r = await call('POST', `/users/${ids.member}/toggle-active`);
    expect(r.json.data.warning).toBeUndefined();
    await call('POST', `/users/${ids.member}/toggle-active`);
  });

  it('Reset password is refused for an Active Directory account and leaves it untouched', async () => {
    const r = await call('POST', `/users/${ids.adacct}/reset-password`, { password: 'Temporary#12345' });
    expect(r.status).toBe(409);
    expect(r.json.error.code).toBe('ERR-AD-ACCOUNT');
    const { rows } = await pool.query('SELECT password_hash, must_change_password FROM idp_users WHERE id = $1', [ids.adacct]);
    expect(rows[0].password_hash).toBeNull();
    expect(rows[0].must_change_password).toBe(false);
    expect(mockRevoke).not.toHaveBeenCalled();
  });

  it('Reset password still works for a local account and forces a change', async () => {
    const r = await call('POST', `/users/${ids.localacct}/reset-password`, { password: 'Temporary#12345' });
    expect(r.status).toBe(200);
    const { rows } = await pool.query('SELECT password_hash, must_change_password FROM idp_users WHERE id = $1', [ids.localacct]);
    expect(rows[0].password_hash).not.toBe('old-hash');
    expect(rows[0].must_change_password).toBe(true);
  });
});

describe('a temporary password follows the platform password rules', () => {
  it('Reset password refuses a short, a common and a name-containing password, and leaves the account and its sessions untouched', async () => {
    for (const password of ['short', 'password123', `${TAG}-localacct-1`]) {
      const r = await call('POST', `/users/${ids.localacct}/reset-password`, { password });
      expect(r.status).toBe(400);
      expect(r.json.error.code).toBe('ERR-VALIDATION-FAILED');
    }
    expect(mockRevoke).not.toHaveBeenCalled();
  });

  it('creating a user refuses a weak temporary password and creates nothing', async () => {
    const r = await call('POST', '/users', { email: email('weak'), given_name: 'Weak', family_name: 'Pass', password: 'password123' });
    expect(r.status).toBe(400);
    const { rows } = await pool.query('SELECT 1 FROM idp_users WHERE email = $1', [email('weak')]);
    expect(rows).toHaveLength(0);
  });
});

describe("a new user's identity follows the same limits in the route, the table and the form", () => {
  const created = async (e: string) => (await pool.query('SELECT 1 FROM idp_users WHERE email = $1', [e])).rows.length;

  it('refuses an address that is not one, one with a space and one that is too long, and creates nothing', async () => {
    for (const [name, bad] of [
      ['nodot', 'someone@localhost'],
      ['noat', 'someone-at-example.invalid'],
      ['space', 'some one@example.invalid'],
      ['long', `${'a'.repeat(250)}@example.invalid`],
    ] as const) {
      const r = await call('POST', '/users', { email: bad, given_name: 'Bad', family_name: name, password: 'Temporary#12345' });
      expect(r.status).toBe(400);
      expect(r.json.error.code).toBe('ERR-VALIDATION-FAILED');
      expect(r.json.error.details[0].field).toBe('email');
      expect(await created(bad.trim().toLowerCase())).toBe(0);
    }
  });

  it('refuses a name longer than 100 characters, or with a control character, naming the field', async () => {
    const tooLong = await call('POST', '/users', { email: email('longname'), given_name: 'x'.repeat(101), family_name: 'Ok', password: 'Temporary#12345' });
    expect(tooLong.status).toBe(400);
    expect(tooLong.json.error.details).toEqual([{ field: 'given_name', message: 'First name can be at most 100 characters.' }]);
    const control = await call('POST', '/users', { email: email('ctrl'), given_name: 'Ok', family_name: 'Bad\u0000Name', password: 'Temporary#12345' });
    expect(control.status).toBe(400);
    expect(control.json.error.details[0].field).toBe('family_name');
    expect(await created(email('longname'))).toBe(0);
    expect(await created(email('ctrl'))).toBe(0);
  });

  it('accepts names of exactly 100 characters (the boundary the table also allows)', async () => {
    const r = await call('POST', '/users', { email: email('boundary'), given_name: 'g'.repeat(100), family_name: 'f'.repeat(100), password: 'Temporary#12345' });
    expect(r.status).toBe(200);
    expect(await created(email('boundary'))).toBe(1);
  });

  it('refuses an office id that is not a whole number instead of passing NaN or 1.5 on', async () => {
    for (const office_id of ['abc', '1.5', '-3', '0']) {
      const r = await call('POST', '/users', { email: email('office'), given_name: 'O', family_name: 'Ffice', password: 'Temporary#12345', office_id });
      expect(r.status).toBe(400);
      expect(r.json.error.details[0].field).toBe('office_id');
    }
    expect(await created(email('office'))).toBe(0);
  });

  it('publishes the limits the form must use, including the live password minimum', async () => {
    const r = await call('GET', '/role-catalog');
    expect(r.status).toBe(200);
    expect(r.json.data.limits).toEqual({ email: 254, name: 100, passwordMinLength: expect.any(Number), passwordMaxLength: 200 });
    expect(r.json.data.limits.passwordMinLength).toBeGreaterThanOrEqual(8);
  });
});

describe('a newly created user must choose a password at first sign-in', () => {
  it('creates with must_change_password = TRUE', async () => {
    const r = await call('POST', '/users', { email: email('created'), given_name: 'New', family_name: 'Person', password: 'Temporary#12345' });
    expect(r.status).toBe(200);
    const { rows } = await pool.query('SELECT must_change_password, source FROM idp_users WHERE email = $1', [email('created')]);
    expect(rows[0]).toEqual({ must_change_password: true, source: 'local' });
  });
});

describe('Sessions list shows the sign-in address', () => {
  it('takes it from the successful sign-in record that created the session', async () => {
    const loginTs = Math.floor(Date.now() / 1000) - 60;
    await pool.query(
      `INSERT INTO oidc_artifacts (id, kind, payload, expires_at) VALUES ($1, 'Session', $2::jsonb, NOW() + INTERVAL '1 hour')`,
      [`${TAG}-s1`, JSON.stringify({ accountId: ids.member, loginTs })],
    );
    await pool.query(
      `INSERT INTO oidc_artifacts (id, kind, payload, expires_at) VALUES ($1, 'Session', $2::jsonb, NOW() + INTERVAL '1 hour')`,
      [`${TAG}-s2`, JSON.stringify({ accountId: ids.localacct, loginTs })],
    );
    // member: a failed attempt (ignored), a matching success, and a much older success (outside the window)
    await pool.query(
      `INSERT INTO idp_login_events (email, success, ip, user_agent, created_at) VALUES
        ($1, FALSE, '203.0.113.9', 'x', NOW() - INTERVAL '70 seconds'),
        ($1, TRUE, '198.51.100.7', 'Jest Browser', NOW() - INTERVAL '65 seconds'),
        ($1, TRUE, '192.0.2.1', 'Old Browser', NOW() - INTERVAL '3 days')`,
      [email('member')],
    );
    const r = await call('GET', '/sessions?limit=100');
    expect(r.status).toBe(200);
    const mine = (r.json.data.sessions as any[]).filter((s) => String(s.id).startsWith(TAG));
    const s1 = mine.find((s) => s.id === `${TAG}-s1`);
    const s2 = mine.find((s) => s.id === `${TAG}-s2`);
    expect(s1.ip).toBe('198.51.100.7');
    expect(s1.user_agent).toBe('Jest Browser');
    expect(s2.ip).toBeNull(); // no sign-in record near its login time
  });
});

describe('Sign-ins page date filter', () => {
  it('filters by from/to (inclusive) and ignores nonsense dates', async () => {
    await pool.query(
      `INSERT INTO idp_login_events (email, success, ip, created_at) VALUES
        ($1, TRUE, '10.0.0.1', '2026-01-10 12:00:00+00'),
        ($1, TRUE, '10.0.0.2', '2026-01-20 12:00:00+00'),
        ($1, FALSE, '10.0.0.3', '2026-01-30 12:00:00+00')`,
      [email('member')],
    );
    const q = (qs: string) => call('GET', `/logins?${qs}`).then((r) => (r.json.data.logins as any[]).filter((l) => l.email === email('member')).map((l) => l.ip).sort());
    expect(await q('from=2026-01-15&to=2026-01-25')).toEqual(['10.0.0.2']);
    expect(await q('from=2026-01-20&to=2026-01-20')).toEqual(['10.0.0.2']);
    expect(await q('to=2026-01-15')).toEqual(['10.0.0.1']);
    expect(await q('from=2026-01-25&to=2026-02-01&filter=failed')).toEqual(['10.0.0.3']);
    expect((await q('from=not-a-date&to=2026-02-30')).length).toBeGreaterThanOrEqual(3); // both ignored: no range
    const meta = await call('GET', '/logins?from=2026-01-15');
    expect(meta.json.data.retentionDays).toBe(90);
    expect(meta.json.data.filters.from).toBe('2026-01-15');
  });
});

describe('Keys is the platform administrator only', () => {
  it('a console administrator gets 403', async () => {
    const r = await call('GET', '/keys');
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
  });
});

describe('Dashboard user count', () => {
  it('reports the total and how many are Active Directory accounts', async () => {
    const r = await call('GET', '/stats');
    expect(r.status).toBe(200);
    expect(r.json.data.userCount).toBeGreaterThanOrEqual(5);
    expect(r.json.data.adUserCount).toBeGreaterThanOrEqual(1);
    expect(r.json.data.adUserCount).toBeLessThanOrEqual(r.json.data.userCount);
  });
});
