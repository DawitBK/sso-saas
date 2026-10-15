/**
 * "Forgot your password?" with no mail server (auth/reset-requests.ts, api/v1/reset-requests.router.ts), over real HTTP against the dev
 * `idp` database with scratch accounts (removed in afterAll). Admin authentication and the audit writer are mocked.
 *
 * Proves: the public answer is identical for every address (no account enumeration); a request is recorded only for a real, active, local
 * account that has a password; asking again refreshes the one open request instead of adding another; the note is cleaned and capped; the
 * switch in Settings turns the whole thing off; administrators see the open requests, dismiss one only with a CSRF token, and an
 * administrator's password reset closes the person's request.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';

const mockAudit = jest.fn(async (..._a: unknown[]) => undefined);
const mockSession = { accountId: 'jest-reset-admin', name: 'Jest Admin', email: 'jest-reset-admin@example.invalid', groups: [] as string[], createdAt: 0 };

jest.mock('../src/admin/requireAdmin.js', () => {
  const gate = () => (req: { adminSession?: unknown }, _res: unknown, next: () => void) => {
    req.adminSession = mockSession;
    next();
  };
  return { requireAdminJson: gate, getPortalSessionFromRequest: jest.fn() };
});
jest.mock('../src/admin/audit.js', () => ({
  writeAudit: (...a: unknown[]) => mockAudit(...a),
  recentAudit: jest.fn(),
  countAuditRows: jest.fn(),
  verifyAuditChain: jest.fn(),
}));

import express from 'express';
import { pool } from '../src/db/pool.js';
import { ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { RESET_REQUEST_ANSWER, publicResetRequestRouter, resetRequestsAdminRouter } from '../src/api/v1/reset-requests.router.js';
import { closeRequestsForUser, listOpenResetRequests, purgeResetRequests } from '../src/auth/reset-requests.js';
import { loadSettings, resetSetting, setSetting } from '../src/settings/store.js';

const TAG = 'jest-reset-req';
const email = (n: string) => `${TAG}-${n}@example.invalid`;
const CSRF = 'csrf-token-for-jest-reset';
const ids: Record<string, string> = {};

let server: http.Server;
let base = '';

async function ask(body: Record<string, unknown> | string) {
  const res = await fetch(`${base}/auth/password-reset-request`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  return { status: res.status, json: (await res.json()) as any };
}

async function admin(method: 'GET' | 'POST', path: string, csrf: string | null = CSRF) {
  const res = await fetch(`${base}/admin/password-reset-requests${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(csrf ? { cookie: `${ADMIN_API_CSRF_COOKIE}=${csrf}` } : {}) },
    body: method === 'POST' ? JSON.stringify({ csrf: csrf ?? 'none' }) : undefined,
  });
  return { status: res.status, json: (await res.json()) as any };
}

const open = async (n: string) =>
  (await pool.query('SELECT id, note, status, handled_by FROM idp_password_reset_requests WHERE user_id = $1 ORDER BY id', [ids[n]])).rows;

async function mkUser(n: string, opts: { source?: string; active?: boolean; hash?: string | null; name?: [string, string] } = {}) {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active)
     VALUES ($1, TRUE, $2, $3, $4, $5, $6) RETURNING id`,
    [email(n), opts.name?.[0] ?? 'Jest', opts.name?.[1] ?? n, opts.hash === undefined ? 'hash' : opts.hash, opts.source ?? 'local', opts.active ?? true],
  );
  ids[n] = rows[0].id;
}

async function cleanup() {
  await pool.query('DELETE FROM idp_users WHERE email LIKE $1', [`${TAG}-%`]); // requests go with them (ON DELETE CASCADE)
}

beforeAll(async () => {
  await cleanup();
  await loadSettings();
  await mkUser('maria', { name: ['Maria', 'Tesfaye'] });
  await mkUser('adperson', { source: 'ad', hash: null });
  await mkUser('disabled', { active: false });
  await mkUser('nopass', { hash: null });
  const app = express();
  app.use('/api/v1/auth/password-reset-request', publicResetRequestRouter());
  app.use('/api/v1/admin/password-reset-requests', resetRequestsAdminRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1`;
});

beforeEach(() => mockAudit.mockClear());

afterAll(async () => {
  await resetSetting('password.allowResetRequests');
  await cleanup();
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
});

describe('the public form', () => {
  it('answers every address the same way, whether or not it has an account', async () => {
    const answers = [];
    for (const body of [
      { email: email('maria') },
      { email: 'nobody-at-all@example.invalid' },
      { email: email('adperson') },
      { email: email('disabled') },
      { email: email('nopass') },
      { email: 'not-an-email' },
      { email: 12345 },
      {},
    ]) {
      const r = await ask(body);
      answers.push([r.status, r.json.data?.message]);
    }
    for (const a of answers) expect(a).toEqual([200, RESET_REQUEST_ANSWER]);
  });

  it('a body that is not an object is refused by the JSON parser (the app error handler shapes it), never recorded', async () => {
    const res = await fetch(`${base}/auth/password-reset-request`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: 'null' });
    expect(res.status).toBe(400);
  });

  it('records a request only for a real, active, local account that has a password', async () => {
    expect(await open('maria')).toHaveLength(1);
    for (const n of ['adperson', 'disabled', 'nopass']) expect(await open(n)).toHaveLength(0);
  });

  it('asking again refreshes the one open request instead of adding another, and the note is cleaned and capped', async () => {
    await ask({ email: email('maria').toUpperCase(), note: `Maria, reception\u0000\n<script>alert(1)</script>${'x'.repeat(400)}` });
    const rows = await open('maria');
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('open');
    expect(rows[0].note.length).toBeLessThanOrEqual(200);
    expect(rows[0].note).toMatch(/^Maria, reception/);
    expect(rows[0].note).not.toMatch(/[\u0000\n]/);
  });

  it('records nothing once an administrator has switched requests off', async () => {
    await pool.query("UPDATE idp_password_reset_requests SET status = 'dismissed', handled_at = NOW() WHERE user_id = $1", [ids.maria]);
    expect((await setSetting('password.allowResetRequests', false, 'jest')).ok).toBe(true);
    const r = await ask({ email: email('maria') });
    expect(r.json.data.message).toBe(RESET_REQUEST_ANSWER);
    expect((await open('maria')).filter((x) => x.status === 'open')).toHaveLength(0);
    await resetSetting('password.allowResetRequests');
    await ask({ email: email('maria') });
    expect((await open('maria')).filter((x) => x.status === 'open')).toHaveLength(1);
  });
});

describe('what administrators see and do', () => {
  it('lists the open requests with the person’s name and note, never anything secret', async () => {
    const r = await admin('GET', '');
    expect(r.status).toBe(200);
    const mine = r.json.data.requests.find((x: { email: string }) => x.email === email('maria'));
    expect(mine).toMatchObject({ name: 'Maria Tesfaye', userId: ids.maria });
    expect(JSON.stringify(r.json)).not.toMatch(/password_hash|"hash"|requested_ip|requestedIp/);
    expect(typeof r.json.data.csrf).toBe('string');
  });

  it('dismisses a request only with a CSRF token, audits it, and then it is no longer open', async () => {
    const id = (await listOpenResetRequests()).find((x) => x.email === email('maria'))!.id;
    expect((await admin('POST', `/${id}/dismiss`, null)).status).toBe(403);
    expect((await open('maria')).filter((x) => x.status === 'open')).toHaveLength(1);

    const ok = await admin('POST', `/${id}/dismiss`);
    expect(ok.status).toBe(200);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), mockSession.email, 'password_reset_request.dismiss', email('maria'), {});
    expect((await open('maria')).filter((x) => x.status === 'open')).toHaveLength(0);

    expect((await admin('POST', `/${id}/dismiss`)).status).toBe(404);
    expect((await admin('POST', '/not-a-number/dismiss')).status).toBe(404);
  });

  it('an administrator’s password reset closes the person’s open request as done', async () => {
    await ask({ email: email('maria') });
    await closeRequestsForUser(ids.maria, 'someone@example.invalid');
    const rows = await open('maria');
    expect(rows.filter((x) => x.status === 'open')).toHaveLength(0);
    expect(rows.some((x) => x.status === 'done' && x.handled_by === 'someone@example.invalid')).toBe(true);
  });

  it('housekeeping removes old handled requests and stale open ones, and keeps recent ones', async () => {
    await pool.query("DELETE FROM idp_password_reset_requests WHERE user_id = $1", [ids.maria]);
    await pool.query(
      `INSERT INTO idp_password_reset_requests (user_id, email, status, requested_at, handled_at) VALUES
        ($1, $2, 'done', NOW() - INTERVAL '120 days', NOW() - INTERVAL '100 days'),
        ($1, $2, 'dismissed', NOW() - INTERVAL '10 days', NOW() - INTERVAL '5 days')`,
      [ids.maria, email('maria')],
    );
    await pool.query(`INSERT INTO idp_password_reset_requests (user_id, email, status, requested_at) VALUES ($1, $2, 'open', NOW() - INTERVAL '40 days')`, [ids.maria, email('maria')]);
    await purgeResetRequests();
    const rows = await open('maria');
    expect(rows.map((r) => r.status)).toEqual(['dismissed']);
  });
});
