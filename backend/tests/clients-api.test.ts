/**
 * The relying-party management API (api/v1/clients.router.ts) over real HTTP against the dev `idp` database. Admin authentication,
 * the platform-administrator check and the audit writer are mocked; the router, the validation, the table and the live client
 * lookup oidc-provider uses are real. The three seeded clients are put back exactly as they were in afterAll.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';

const mockAudit = jest.fn(async (..._a: unknown[]) => undefined);
const state = { platform: false };
const mockSession = { accountId: 'jest-clients-admin', name: 'Jest Admin', email: 'jest-clients@example.invalid', groups: [] as string[], createdAt: 0 };

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
import { IDP_CONFIG } from '../src/config.js';
import { ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { clientsRouter } from '../src/api/v1/clients.router.js';
import { findClientMetadata } from '../src/oidc/clients.js';

const CSRF = 'csrf-token-for-jest-clients';
let server: http.Server;
let base = '';
let saved: Array<Record<string, unknown>> = [];

async function call(method: 'GET' | 'PUT' | 'POST', path: string, body?: Record<string, unknown>, csrf: string | null = CSRF) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(csrf ? { cookie: `${ADMIN_API_CSRF_COOKIE}=${csrf}` } : {}) },
    body: method === 'GET' ? undefined : JSON.stringify({ ...(body ?? {}), csrf: csrf ?? 'none' }),
  });
  return { status: res.status, text: await res.text() };
}
const json = (r: { text: string }) => JSON.parse(r.text);
const row = async (id: string) => (await pool.query('SELECT * FROM idp_clients WHERE client_id = $1', [id])).rows[0];
const seed = (id: string) => IDP_CONFIG.clientSeed.find((c) => c.client_id === id)!;

beforeAll(async () => {
  saved = (await pool.query('SELECT * FROM idp_clients WHERE client_id = ANY($1::text[])', [['edams', 'gms', 'portal']])).rows;
  expect(saved.map((r) => r.client_id).sort()).toEqual(['edams', 'gms', 'portal']);
  const app = express();
  app.use('/api/v1/admin/clients', clientsRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1/admin/clients`;
});

beforeEach(() => {
  mockAudit.mockClear();
  state.platform = false;
});

afterAll(async () => {
  for (const r of saved) {
    await pool.query(
      `UPDATE idp_clients SET client_secret = $2, redirect_uris = $3, post_logout_redirect_uris = $4, is_active = $5,
              secret_rotated_at = $6, updated_by = $7, updated_at = $8 WHERE client_id = $1`,
      [r.client_id, r.client_secret, r.redirect_uris, r.post_logout_redirect_uris, r.is_active, r.secret_rotated_at, r.updated_by, r.updated_at],
    );
  }
  await pool.query(`DELETE FROM oidc_artifacts WHERE id LIKE 'jest-clients-%'`);
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
});

describe('reading', () => {
  it('lists every seeded client with state, scopes, addresses and usage, and never the secret', async () => {
    const r = await call('GET', '/');
    expect(r.status).toBe(200);
    const body = json(r).data;
    expect(body.clients.map((c: any) => c.clientId)).toEqual(IDP_CONFIG.clientSeed.map((c) => c.client_id));
    const edams = body.clients.find((c: any) => c.clientId === 'edams');
    expect(edams).toMatchObject({ authMethod: 'client_secret_post', rolesScope: 'edams_roles', active: true });
    expect(edams.scopes).toEqual(expect.arrayContaining(['openid', 'edams_roles']));
    expect(edams.usage).toEqual(expect.objectContaining({ activeGrants: expect.any(Number), activeRefreshTokens: expect.any(Number) }));
    expect(body.protectedClients).toEqual(['portal']);
    for (const s of saved) expect(r.text).not.toContain(String(s.client_secret));
    expect(r.text).not.toMatch(/"clientSecret"|"client_secret"|"secret"/);
  });

  it('one client by id, and 404 for an id that is not one of ours', async () => {
    expect((await call('GET', '/edams')).status).toBe(200);
    expect((await call('GET', '/retail-os')).status).toBe(404);
  });
});

describe('changing addresses', () => {
  it('is the platform administrator’s alone', async () => {
    const r = await call('PUT', '/edams/uris', { redirectUris: ['https://x.example/cb'], postLogoutRedirectUris: [] });
    expect(r.status).toBe(403);
    expect(json(r).error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    expect(mockAudit).not.toHaveBeenCalled();
  });

  it('needs a CSRF token', async () => {
    state.platform = true;
    expect((await call('PUT', '/edams/uris', { redirectUris: ['https://x.example/cb'] }, null)).status).toBe(403);
  });

  it('stores valid addresses, audits old and new, and the live client lookup sees them at once', async () => {
    state.platform = true;
    const before = await row('edams');
    const redirect = [...before.redirect_uris, 'https://portal.example.test/dms/auth/callback'];
    const r = await call('PUT', '/edams/uris', { redirectUris: redirect, postLogoutRedirectUris: before.post_logout_redirect_uris });
    expect(r.status).toBe(200);
    const after = await row('edams');
    expect(after.redirect_uris).toEqual(redirect);
    expect(after.updated_by).toBe('platform');
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), 'jest-clients@example.invalid', 'client.uris.update', 'edams', {
      before: { redirect: before.redirect_uris, logout: before.post_logout_redirect_uris },
      after: { redirect: redirect, logout: before.post_logout_redirect_uris },
    });
    expect(json(r).data.client).toMatchObject({ redirectUris: redirect, urisDrift: true });
    // What oidc-provider asks for on its next request:
    const live = await findClientMetadata('edams');
    expect(live?.redirect_uris).toEqual(redirect);
  });

  it('refuses unsafe addresses and changes nothing', async () => {
    state.platform = true;
    const before = await row('edams');
    for (const bad of [['http://portal.example.test/cb'], ['https://*.example.test/cb'], ['https://x.example/cb#f'], []]) {
      const r = await call('PUT', '/edams/uris', { redirectUris: bad });
      expect({ bad, status: r.status }).toEqual({ bad, status: 400 });
    }
    expect((await row('edams')).redirect_uris).toEqual(before.redirect_uris);
  });

  it('keeps the GMS bridge’s own callback registered', async () => {
    state.platform = true;
    const r = await call('PUT', '/gms/uris', { redirectUris: ['https://elsewhere.example.test/cb'] });
    expect(r.status).toBe(400);
    expect(json(r).error.message).toMatch(/bridge\/gms\/callback/);
  });

  it('refuses to edit the portal client, which the console itself signs in through', async () => {
    state.platform = true;
    const r = await call('PUT', '/portal/uris', { redirectUris: ['https://x.example/cb'] });
    expect(r.status).toBe(409);
    expect(json(r).error.code).toBe('ERR-CLIENT-PROTECTED');
  });

  it('"restore" puts the configured addresses back, including for the portal client', async () => {
    state.platform = true;
    const r = await call('POST', '/edams/restore-uris', {});
    expect(r.status).toBe(200);
    expect((await row('edams')).redirect_uris).toEqual(seed('edams').redirect_uris);
    expect(json(r).data.client.urisDrift).toBe(false);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'client.uris.restore', 'edams', expect.any(Object));
    expect((await call('POST', '/portal/restore-uris', {})).status).toBe(200);
  });
});

describe('switching a client off and on', () => {
  it('off ends what it already holds and oidc-provider stops finding it; on brings it back', async () => {
    state.platform = true;
    await pool.query(
      `INSERT INTO oidc_artifacts (id, kind, payload, expires_at) VALUES
         ('jest-clients-at', 'AccessToken', '{"clientId":"edams","accountId":"x"}', NOW() + INTERVAL '1 hour'),
         ('jest-clients-rt', 'RefreshToken', '{"clientId":"edams","accountId":"x"}', NOW() + INTERVAL '1 hour'),
         ('jest-clients-other', 'AccessToken', '{"clientId":"gms","accountId":"x"}', NOW() + INTERVAL '1 hour')`,
    );
    const off = await call('PUT', '/edams/active', { active: false });
    expect(off.status).toBe(200);
    expect(json(off).data.revokedArtifacts).toBeGreaterThanOrEqual(2);
    expect(json(off).data.client.active).toBe(false);
    expect(await findClientMetadata('edams')).toBeUndefined();
    const left = await pool.query(`SELECT id FROM oidc_artifacts WHERE id LIKE 'jest-clients-%' ORDER BY id`);
    expect(left.rows.map((r) => r.id)).toEqual(['jest-clients-other']);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'client.disable', 'edams', expect.any(Object));

    const on = await call('PUT', '/edams/active', { active: true });
    expect(on.status).toBe(200);
    expect(await findClientMetadata('edams')).toBeDefined();
  });

  it('refuses to switch the portal client off, and validates the body', async () => {
    state.platform = true;
    expect((await call('PUT', '/portal/active', { active: false })).status).toBe(409);
    expect((await call('PUT', '/edams/active', { active: 'no' })).status).toBe(400);
  });

  it('is the platform administrator’s alone', async () => {
    expect((await call('PUT', '/edams/active', { active: false })).status).toBe(403);
  });
});

describe('rotating a secret', () => {
  it('needs the application id typed, returns the new secret exactly once, never audits it', async () => {
    state.platform = true;
    const old = (await row('gms')).client_secret as string;
    const wrong = await call('POST', '/gms/rotate-secret', { confirm: 'nope' });
    expect(wrong.status).toBe(400);
    expect((await row('gms')).client_secret).toBe(old);

    const ok = await call('POST', '/gms/rotate-secret', { confirm: 'gms' });
    expect(ok.status).toBe(200);
    const { secret, client } = json(ok).data;
    expect(typeof secret).toBe('string');
    expect(secret.length).toBeGreaterThanOrEqual(60);
    expect((await row('gms')).client_secret).toBe(secret);
    expect(client.secretRotatedAt).not.toBeNull();
    expect(client.secretIsDevDefault).toBe(false);
    expect(ok.text.split(secret).length - 1).toBe(1);

    const listed = await call('GET', '/');
    expect(listed.text).not.toContain(secret);
    // (the first argument is the request object; the audit detail is what matters)
    expect(JSON.stringify(mockAudit.mock.calls.map((c) => c.slice(1)))).not.toContain(secret);
    expect(mockAudit).toHaveBeenCalledWith(expect.anything(), expect.anything(), 'client.secret.rotate', 'gms', {});
    // oidc-provider authenticates the client with the new value from the next request.
    expect((await findClientMetadata('gms'))?.client_secret).toBe(secret);
  });

  it('is refused for the portal client and for anyone but the platform administrator', async () => {
    state.platform = true;
    expect((await call('POST', '/portal/rotate-secret', { confirm: 'portal' })).status).toBe(409);
    state.platform = false;
    expect((await call('POST', '/gms/rotate-secret', { confirm: 'gms' })).status).toBe(403);
  });
});
