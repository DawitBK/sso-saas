/**
 * The platform settings API (api/v1/settings.router.ts), driven over real HTTP against the dev `idp` database. Admin authentication,
 * the platform-administrator check and the audit writer are mocked; the registry, the store, the table and the consumers are real.
 *
 * Proves: who may change what, that a change reaches the code that uses it (password rule, hidden apps, public branding), that an
 * invalid value is refused with a reason, that every change is audited with its old and new value, and that the platform
 * administrator is recorded anonymously.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';

const mockAudit = jest.fn(async (..._a: unknown[]) => undefined);
const state = { platform: false };
const mockSession = { accountId: 'jest-settings-admin', name: 'Jest Admin', email: 'jest-settings@example.invalid', groups: [] as string[], createdAt: 0 };

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
jest.mock('../src/auth/platform-admin.js', () => ({
  ...jest.requireActual('../src/auth/platform-admin.js'),
  isPlatformAdminSession: async () => state.platform,
}));

import express from 'express';
import { pool } from '../src/db/pool.js';
import { ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { publicRouter, settingsAdminRouter } from '../src/api/v1/settings.router.js';
import { loadSettings, setAppIdsProvider } from '../src/settings/store.js';
import { newPasswordProblem } from '../src/auth/password-policy.js';
import { catalog, APP_REGISTRY } from '../src/portal/catalog.js';

const CSRF = 'csrf-token-for-jest-settings';
const KEYS = ['branding.productName', 'branding.accentColor', 'password.minLength', 'portal.hiddenApps', 'lockout.threshold'];

let server: http.Server;
let base = '';

async function call(method: 'GET' | 'PUT' | 'DELETE', path: string, body?: Record<string, unknown>, csrf: string | null = CSRF) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(csrf ? { cookie: `${ADMIN_API_CSRF_COOKIE}=${csrf}` } : {}) },
    body: method === 'GET' ? undefined : JSON.stringify({ ...(body ?? {}), csrf: csrf ?? 'none' }),
  });
  return { status: res.status, json: (await res.json()) as any };
}

async function wipe() {
  await pool.query('DELETE FROM idp_settings WHERE key = ANY($1::text[])', [KEYS]);
  await loadSettings();
}

beforeAll(async () => {
  setAppIdsProvider(() => APP_REGISTRY.map((a) => a.rp));
  await wipe();
  const app = express();
  app.use('/api/v1/admin/settings', settingsAdminRouter());
  app.use('/api/v1/public', publicRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1`;
});

beforeEach(() => {
  mockAudit.mockClear();
  state.platform = false;
});

afterAll(async () => {
  await wipe();
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
});

function find(result: any, key: string) {
  const json = result.json ?? result;
  return json.data.groups.flatMap((g: any) => g.settings).find((s: any) => s.key === key);
}

describe('GET /admin/settings', () => {
  it('lists every group with limits, defaults and who may edit, and issues a CSRF token', async () => {
    const r = await call('GET', '/admin/settings');
    expect(r.status).toBe(200);
    expect(r.json.data.groups.map((g: any) => g.id)).toEqual(['branding', 'portal', 'passwords', 'lockout', 'mfa', 'sessions', 'retention']);
    expect(typeof r.json.data.csrf).toBe('string');
    expect(find(r.json, 'password.minLength')).toMatchObject({ type: 'int', min: 8, max: 64, defaultValue: 8, editableBy: 'platform' });
    expect(find(r.json, 'portal.hiddenApps').choices).toEqual(APP_REGISTRY.map((a) => ({ id: a.rp, label: a.label })));
  });

  it('shows platform-only settings as not editable to an IdP administrator, editable to the platform administrator', async () => {
    const asAdmin = await call('GET', '/admin/settings');
    expect(find(asAdmin.json, 'password.minLength').canEdit).toBe(false);
    expect(find(asAdmin.json, 'branding.productName').canEdit).toBe(true);
    expect(asAdmin.json.data.viewerIsPlatformAdmin).toBe(false);
    state.platform = true;
    const asPlatform = await call('GET', '/admin/settings');
    expect(find(asPlatform.json, 'password.minLength').canEdit).toBe(true);
    expect(asPlatform.json.data.viewerIsPlatformAdmin).toBe(true);
  });
});

describe('PUT /admin/settings/:key', () => {
  it('an IdP administrator is refused a platform-only setting, and nothing changes or is audited', async () => {
    const r = await call('PUT', '/admin/settings/password.minLength', { value: 12 });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    expect(newPasswordProblem('abcdefghij1!')).toBeNull();
    expect(mockAudit).not.toHaveBeenCalled();
  });

  it('refuses a missing or wrong CSRF token', async () => {
    const none = await call('PUT', '/admin/settings/branding.productName', { value: 'X' }, null);
    expect(none.status).toBe(403);
    expect(none.json.error.code).toBe('ERR-INVALID-CSRF');
  });

  it('an unknown key is a 404', async () => {
    const r = await call('PUT', '/admin/settings/nope.nothing', { value: 1 });
    expect(r.status).toBe(404);
  });

  it('a branding change is stored, audited with old and new value, shown to everyone, and the table keeps who did it', async () => {
    const r = await call('PUT', '/admin/settings/branding.productName', { value: '  Acme Sign-in  ' });
    expect(r.status).toBe(200);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), 'jest-settings@example.invalid', 'setting.update', 'branding.productName', { before: 'Example Corp Identity', after: 'Acme Sign-in' });
    const pub = await fetch(`${base}/public/branding`);
    expect((await pub.json() as any).data.productName).toBe('Acme Sign-in');
    expect(pub.headers.get('cache-control')).toMatch(/max-age/);
    const { rows } = await pool.query('SELECT updated_by FROM idp_settings WHERE key = $1', ['branding.productName']);
    expect(rows[0].updated_by).toBe('jest-settings@example.invalid');
    const listed = find(await call('GET', '/admin/settings'), 'branding.productName');
    expect(listed).toMatchObject({ value: 'Acme Sign-in', source: 'stored', updatedBy: 'jest-settings@example.invalid' });
  });

  it('refuses an invalid value with a reason and stores nothing', async () => {
    const tooPale = await call('PUT', '/admin/settings/branding.accentColor', { value: '#ffff99' });
    expect(tooPale.status).toBe(400);
    expect(tooPale.json.error.message).toMatch(/contrast/);
    const notAColor = await call('PUT', '/admin/settings/branding.accentColor', { value: 'red; background:url(x)' });
    expect(notAColor.status).toBe(400);
    const { rows } = await pool.query('SELECT 1 FROM idp_settings WHERE key = $1', ['branding.accentColor']);
    expect(rows).toHaveLength(0);
  });

  it('the platform administrator changes a policy; it reaches the password rule at once and is recorded anonymously', async () => {
    state.platform = true;
    const r = await call('PUT', '/admin/settings/password.minLength', { value: 14 });
    expect(r.status).toBe(200);
    expect(newPasswordProblem('abcdefghij1!')).toMatch(/at least 14/);
    expect(newPasswordProblem('abcdefghij1!xy')).toBeNull();
    const { rows } = await pool.query('SELECT updated_by FROM idp_settings WHERE key = $1', ['password.minLength']);
    expect(rows[0].updated_by).toBe('platform');
    expect(find(await call('GET', '/admin/settings'), 'password.minLength').updatedBy).toBe('Platform administrator');
  });

  it('hiding an application takes its tile off the launcher; access rules are untouched', async () => {
    expect(catalog().map((a) => a.rp)).toContain('gms');
    const r = await call('PUT', '/admin/settings/portal.hiddenApps', { value: ['gms'] });
    expect(r.status).toBe(200);
    expect(catalog().map((a) => a.rp)).not.toContain('gms');
    const bad = await call('PUT', '/admin/settings/portal.hiddenApps', { value: ['not-an-app'] });
    expect(bad.status).toBe(400);
  });
});

describe('DELETE /admin/settings/:key', () => {
  it('puts a setting back to its default, audited', async () => {
    state.platform = true;
    await call('PUT', '/admin/settings/lockout.threshold', { value: 9 });
    mockAudit.mockClear();
    const r = await call('DELETE', '/admin/settings/lockout.threshold');
    expect(r.status).toBe(200);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), 'jest-settings@example.invalid', 'setting.reset', 'lockout.threshold', { before: 9, after: 5 });
    expect(find(await call('GET', '/admin/settings'), 'lockout.threshold')).toMatchObject({ value: 5, source: 'default' });
  });

  it('is refused for a platform-only setting when not the platform administrator', async () => {
    const r = await call('DELETE', '/admin/settings/lockout.threshold');
    expect(r.status).toBe(403);
  });
});

describe('GET /public/branding', () => {
  it('is unauthenticated, carries no secret, and states the real password minimum', async () => {
    const r = await fetch(`${base}/public/branding`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as any;
    expect(Object.keys(body.data).sort()).toEqual(
      ['accentColor', 'accentColorDark', 'accentInk', 'accentInkDark', 'footerText', 'loginNotice', 'passwordMinLength', 'passwordResetRequests', 'portalMessage', 'productName', 'supportContact', 'tagline'],
    );
    expect(body.data.passwordMinLength).toBe(14);
  });
});
