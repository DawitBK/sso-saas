/**
 * Users CSV export and bulk actions (api/v1/users-bulk.router.ts) over real HTTP against the dev `idp` database with scratch users
 * (removed in afterAll). Admin authentication, the audit writer and session revocation are mocked; the router, the filter builder
 * and the table are real.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';

const mockRevoke = jest.fn();
const mockAudit = jest.fn(async (..._a: unknown[]) => undefined);
const mockSession: { value: { accountId: string; name: string; email: string; groups: string[]; createdAt: number } } = {
  value: { accountId: '', name: 'Jest Admin', email: 'jest-bulk-admin@example.invalid', groups: [], createdAt: 0 },
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
  writeAudit: (...a: unknown[]) => mockAudit(...a),
  recentAudit: jest.fn(),
  countAuditRows: jest.fn(),
  verifyAuditChain: jest.fn(),
}));
jest.mock('../src/admin/dms-internal-client.js', () => {
  class DmsInternalApiError extends Error {
    status = 502;
    code = 'ERR-DMS';
  }
  return { DmsInternalApiError, listDmsGroupsForRole: jest.fn(async () => []) };
});

import express from 'express';
import { pool } from '../src/db/pool.js';
import { ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { csvCell, csvRow, MAX_BULK, usersBulkRouter } from '../src/api/v1/users-bulk.router.js';

const TAG = 'jest-bulk';
const email = (n: string) => `${TAG}-${n}@example.invalid`;
const CSRF = 'csrf-token-for-jest-bulk';
let server: http.Server;
let base = '';
const ids: Record<string, string> = {};

async function call(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>, csrf: string | null = CSRF) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(csrf ? { cookie: `${ADMIN_API_CSRF_COOKIE}=${csrf}` } : {}) },
    body: method === 'POST' ? JSON.stringify({ ...(body ?? {}), csrf: csrf ?? 'none' }) : undefined,
  });
  const bytes = Buffer.from(await res.arrayBuffer());
  const text = bytes.toString('utf8');
  return { status: res.status, text, bytes, headers: res.headers, json: () => JSON.parse(text.replace(/^\uFEFF/, '')) };
}

async function mk(name: string, given: string | null = 'Jest', active = true, totp = false) {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, totp_enabled)
     VALUES ($1, TRUE, $2, $3, 'x', 'local', $4, $5) RETURNING id`,
    [email(name), given, name, active, totp],
  );
  ids[name] = rows[0].id;
}

async function cleanup() {
  await pool.query(`DELETE FROM idp_user_groups WHERE user_id IN (SELECT id FROM idp_users WHERE email LIKE $1)`, [`${TAG}-%`]);
  await pool.query('DELETE FROM idp_users WHERE email LIKE $1', [`${TAG}-%`]);
}

beforeAll(async () => {
  await cleanup();
  await mk('admin');
  await mk('alpha');
  await mk('bravo');
  await mk('charlie', '=HYPERLINK("http://evil.example","click")', true, true);
  await mk('delta', 'Dee', false);
  mockSession.value.accountId = ids.admin;
  const app = express();
  app.use(express.json());
  app.use('/api/v1/admin/users', usersBulkRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1/admin/users`;
});

beforeEach(() => {
  mockRevoke.mockReset();
  mockRevoke.mockResolvedValue({ oidcArtifacts: 1, portalSessions: 0, gatewaySessions: 0, pendingLogins: 0, gmsSessions: 0, dmsNotified: true });
  mockAudit.mockClear();
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await cleanup();
  await pool.end();
});

describe('csvCell / csvRow', () => {
  it('quotes commas, quotes and newlines', () => {
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('two\nlines')).toBe('"two\nlines"');
    expect(csvCell(null)).toBe('');
    expect(csvCell(5)).toBe('5');
  });
  it('defuses spreadsheet formulas (CSV injection)', () => {
    for (const v of ['=1+1', '+1', '-1', '@SUM(A1)', '\tx', '\rx']) expect(csvCell(v).replace(/^"/, '')[0]).toBe("'");
    expect(csvCell('=HYPERLINK("x","y")')).toBe(`"'=HYPERLINK(""x"",""y"")"`);
  });
  it('joins cells with commas', () => {
    expect(csvRow(['a', 'b,c', null])).toBe('a,"b,c",');
  });
});

describe('GET /export', () => {
  it('returns the filtered list as CSV, with a header, a byte-order mark and an audit row', async () => {
    const r = await call('GET', `/export?q=${TAG}-`);
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toMatch(/text\/csv/);
    expect(r.headers.get('content-disposition')).toMatch(/attachment; filename="users-\d{4}-\d{2}-\d{2}\.csv"/);
    // fetch's text() would swallow the byte-order mark, so look at the raw bytes: EF BB BF.
    expect([...r.bytes.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    const lines = r.text.replace(/^\uFEFF/, '').trim().split('\r\n');
    expect(lines[0]).toBe('email,first_name,last_name,account_type,status,two_factor,must_change_password,groups,last_sign_in,created');
    expect(lines).toHaveLength(1 + 5);
    expect(r.headers.get('x-export-rows')).toBe('5');
    expect(r.headers.get('x-export-truncated')).toBe('false');
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), 'jest-bulk-admin@example.invalid', 'users.export', 'users', expect.objectContaining({ rows: 5, truncated: false }));
  });

  it('applies the same filters as the list', async () => {
    const disabled = await call('GET', `/export?q=${TAG}-&status=inactive`);
    expect(disabled.text.replace(/^\uFEFF/, '').trim().split('\r\n')).toHaveLength(2);
    expect(disabled.text).toContain(email('delta'));
    const enrolled = await call('GET', `/export?q=${TAG}-&mfa=enrolled`);
    expect(enrolled.text).toContain(email('charlie'));
    expect(enrolled.text).not.toContain(email('alpha'));
  });

  it('a name that starts like a formula is neutralised in the file', async () => {
    const r = await call('GET', `/export?q=${email('charlie')}`);
    expect(r.text).toContain(`"'=HYPERLINK(""http://evil.example"",""click"")"`);
  });

  it('does not put the search text into the audit row', async () => {
    mockAudit.mockClear();
    await call('GET', `/export?q=${TAG}-`);
    const detail = mockAudit.mock.calls[0]?.[4] as { filters: { q: string } };
    expect(detail.filters.q).toBe('(set)');
    expect(JSON.stringify(detail)).not.toContain(`${TAG}-`);
  });
});

describe('POST /bulk', () => {
  it('needs a CSRF token, a known action and real user ids', async () => {
    expect((await call('POST', '/bulk', { ids: [ids.alpha], action: 'disable' }, null)).status).toBe(403);
    expect((await call('POST', '/bulk', { ids: [ids.alpha], action: 'delete' })).status).toBe(400);
    expect((await call('POST', '/bulk', { ids: ['not-a-uuid'], action: 'disable' })).status).toBe(400);
    expect((await call('POST', '/bulk', { ids: [], action: 'disable' })).status).toBe(400);
    const tooMany = Array.from({ length: MAX_BULK + 1 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`);
    expect((await call('POST', '/bulk', { ids: tooMany, action: 'disable' })).status).toBe(400);
  });

  it('disables several people, signs them out, audits each, and refuses the administrator’s own account', async () => {
    const r = await call('POST', '/bulk', { ids: [ids.alpha, ids.bravo, ids.admin], action: 'disable' });
    expect(r.status).toBe(200);
    const { results, summary } = r.json().data;
    expect(summary).toMatchObject({ changed: 2, skipped: 0, refused: 1 });
    expect(results.find((x: any) => x.id === ids.admin)).toMatchObject({ outcome: 'refused' });
    expect(mockRevoke).toHaveBeenCalledTimes(2);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'user.disable', email('alpha'), expect.objectContaining({ bulk: true }));
    const state = await pool.query('SELECT email, is_active FROM idp_users WHERE email LIKE $1 ORDER BY email', [`${TAG}-%`]);
    const active = Object.fromEntries(state.rows.map((x) => [x.email, x.is_active]));
    expect(active[email('alpha')]).toBe(false);
    expect(active[email('bravo')]).toBe(false);
    expect(active[email('admin')]).toBe(true);
  });

  it('is idempotent: doing it again changes nothing and signs nobody out', async () => {
    const r = await call('POST', '/bulk', { ids: [ids.alpha, ids.bravo], action: 'disable' });
    expect(r.json().data.summary).toMatchObject({ changed: 0, skipped: 2 });
    expect(mockRevoke).not.toHaveBeenCalled();
  });

  it('enables people again', async () => {
    const r = await call('POST', '/bulk', { ids: [ids.alpha, ids.bravo, ids.charlie], action: 'enable' });
    expect(r.json().data.summary).toMatchObject({ changed: 2, skipped: 1 });
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'user.enable', email('alpha'), expect.objectContaining({ bulk: true }));
  });

  it('signs people out everywhere without disabling them', async () => {
    const r = await call('POST', '/bulk', { ids: [ids.alpha, ids.charlie], action: 'sign-out' });
    expect(r.json().data.summary).toMatchObject({ changed: 2 });
    expect(mockRevoke).toHaveBeenCalledTimes(2);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'user.signout_all', email('alpha'), expect.any(Object));
    const { rows } = await pool.query('SELECT is_active FROM idp_users WHERE id = $1', [ids.alpha]);
    expect(rows[0].is_active).toBe(true);
  });

  it('reports an id that does not exist as not found, without failing the rest', async () => {
    const ghost = '11111111-1111-4111-8111-111111111111';
    const r = await call('POST', '/bulk', { ids: [ghost, ids.delta], action: 'enable' });
    const { results, summary } = r.json().data;
    expect(results.find((x: any) => x.id === ghost)).toMatchObject({ outcome: 'refused', message: 'User not found.' });
    expect(summary).toMatchObject({ changed: 1, refused: 1 });
  });
});
