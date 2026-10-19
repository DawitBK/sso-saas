/**
 * The licensing API (api/v1/licenses.router.ts), the service, the token and SSO's own enforcement, driven over real HTTP against the dev `idp`
 * database. Admin authentication, the platform-administrator check and the audit writer are mocked; the router, validation, repository,
 * transactions, token signing (with the real signing key) and the guard are real.
 *
 * Existing licence rows are saved first and put back afterwards, and every license_events row this file wrote is deleted, so a licence an
 * administrator really configured in the dev database survives a test run.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import crypto from 'node:crypto';

const mockAudit = jest.fn(async (..._a: unknown[]) => undefined);
const state = { platform: true, session: true };
const mockSession = { accountId: 'jest-license-admin', name: 'Jest Admin', email: 'jest-license@example.invalid', groups: [] as string[], createdAt: 0 };

jest.mock('../src/admin/requireAdmin.js', () => {
  const gate = () => (req: { adminSession?: unknown }, _res: unknown, next: () => void) => {
    req.adminSession = mockSession;
    next();
  };
  return { requireAdminJson: gate, getPortalSessionFromRequest: async () => (state.session ? mockSession : null) };
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
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { pool } from '../src/db/pool.js';
import { IDP_CONFIG } from '../src/config.js';
import { loadSigningJwks } from '../src/jwks.js';
import { ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { licensesAdminRouter, licensesPublicRouter } from '../src/api/v1/licenses.router.js';
import { licenseReadOnlyGuard } from '../src/licenses/guard.js';
import { invalidateOwnLicense } from '../src/licenses/status.js';
import { resetLicenseTokenCache } from '../src/licenses/token.js';

const CSRF = 'csrf-token-for-jest-licenses';
const DAY = 86_400_000;
const isoDays = (n: number) => new Date(Date.now() + n * DAY).toISOString();

let server: http.Server;
let base = '';
let savedRows: Record<string, unknown>[] = [];
let baselineEventId = 0;

async function call(method: 'GET' | 'PUT' | 'POST' | 'DELETE', path: string, body?: Record<string, unknown>, csrf: string | null = CSRF) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(csrf ? { cookie: `${ADMIN_API_CSRF_COOKIE}=${csrf}` } : {}) },
    body: method === 'GET' ? undefined : JSON.stringify({ ...(body ?? {}), csrf: csrf ?? 'none' }),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

async function clearLicenses() {
  await pool.query('DELETE FROM licenses');
  await pool.query('DELETE FROM license_events WHERE id > $1', [baselineEventId]);
  invalidateOwnLicense();
  resetLicenseTokenCache();
}

beforeAll(async () => {
  savedRows = (await pool.query('SELECT * FROM licenses')).rows;
  baselineEventId = Number((await pool.query('SELECT COALESCE(MAX(id), 0) AS m FROM license_events')).rows[0].m);
  await clearLicenses();
  const app = express();
  // The real guard, with its real dependencies (SSO's own licence row), ahead of everything, exactly as main.ts mounts it.
  app.use(licenseReadOnlyGuard());
  app.use('/api/v1/licenses', licensesPublicRouter());
  app.use('/api/v1/license', licensesPublicRouter());
  app.use('/api/v1/admin/licenses', licensesAdminRouter());
  app.put('/api/v1/admin/settings/:key', (_req, res) => res.json({ reached: true }));
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

beforeEach(async () => {
  mockAudit.mockClear();
  state.platform = true;
  state.session = true;
  await clearLicenses();
});

afterAll(async () => {
  await pool.query('DELETE FROM licenses');
  for (const r of savedRows) {
    await pool.query(
      `INSERT INTO licenses (system, customer, expires_at, grace_days, warn_days, max_users, modules, notes, version, created_at, updated_at, updated_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [r.system, r.customer, r.expires_at, r.grace_days, r.warn_days, r.max_users, r.modules, r.notes, r.version, r.created_at, r.updated_at, r.updated_by],
    );
  }
  await pool.query('DELETE FROM license_events WHERE id > $1', [baselineEventId]);
  invalidateOwnLicense();
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
});

const gmsLicense = { customer: 'Example Corp', expiresAt: '2030-01-01', graceDays: 14, warnDays: 30, maxUsers: 50, modules: ['visits', 'scheduling'] };

describe('access', () => {
  it('an IdP administrator who is not the platform administrator is refused every admin route', async () => {
    state.platform = false;
    for (const [m, p] of [['GET', '/api/v1/admin/licenses'], ['PUT', '/api/v1/admin/licenses/gms'], ['POST', '/api/v1/admin/licenses/gms/extend'], ['DELETE', '/api/v1/admin/licenses/gms'], ['GET', '/api/v1/admin/licenses/gms/events']] as const) {
      const r = await call(m, p, gmsLicense);
      expect(r.status).toBe(403);
      expect(r.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    }
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM licenses')).rows[0].n).toBe(0);
    expect(mockAudit).not.toHaveBeenCalled();
  });

  it('a change needs a valid CSRF token', async () => {
    expect((await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense, null)).status).toBe(403);
    expect((await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense, null)).json.error.code).toBe('ERR-INVALID-CSRF');
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM licenses')).rows[0].n).toBe(0);
  });

  it('an unknown system is a 404', async () => {
    expect((await call('PUT', '/api/v1/admin/licenses/mos', gmsLicense)).status).toBe(404);
    expect((await call('GET', '/api/v1/admin/licenses/mos/events')).status).toBe(404);
  });
});

describe('GET /admin/licenses', () => {
  it('lists the three systems with no licence, the module catalogue and a CSRF token', async () => {
    const r = await call('GET', '/api/v1/admin/licenses');
    expect(r.status).toBe(200);
    expect(r.json.data.systems.map((s: any) => s.system)).toEqual(['sso', 'gms', 'dms']);
    for (const s of r.json.data.systems) {
      expect(s.license).toBeNull();
      expect(s.computed.state).toBe('unconfigured');
      expect(s.events).toEqual([]);
    }
    expect(r.json.data.systems[1].modules.map((m: any) => m.key)).toEqual(['visits', 'scheduling', 'checkin', 'credentials', 'notifications', 'ocr']);
    expect(r.json.data.systems[0].modules).toEqual([]);
    expect(typeof r.json.data.csrf).toBe('string');
    expect(r.json.data.enforcement).toBe(IDP_CONFIG.licenseEnforcement);
  });
});

describe('save (PUT)', () => {
  it('refuses invalid input with the field named', async () => {
    const r = await call('PUT', '/api/v1/admin/licenses/gms', { customer: '', expiresAt: '2030-02-30', graceDays: 400, maxUsers: 0, modules: ['nope'] });
    expect(r.status).toBe(400);
    expect(r.json.error.code).toBe('ERR-VALIDATION-FAILED');
    expect(r.json.error.details.map((d: any) => d.field).sort()).toEqual(['customer', 'expiresAt', 'graceDays', 'maxUsers', 'modules']);
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM licenses')).rows[0].n).toBe(0);
  });

  it('creates a licence (201), writes an event and an audit entry in the same transaction, and has no seed rows before it', async () => {
    const r = await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    expect(r.status).toBe(201);
    expect(r.json.data.action).toBe('create');
    expect(r.json.data.license).toMatchObject({ system: 'gms', customer: 'Example Corp', expiresAt: '2030-01-01T23:59:59.999Z', graceDays: 14, warnDays: 30, maxUsers: 50, modules: ['visits', 'scheduling'], version: expect.any(Number), updatedBy: 'platform' });
    expect(r.json.data.computed.state).toBe('active');

    const events = (await pool.query("SELECT action, actor, version, before, after FROM license_events WHERE id > $1 AND system = 'gms'", [baselineEventId])).rows;
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ action: 'create', actor: 'platform', before: null });
    expect(events[0].after.customer).toBe('Example Corp');

    expect(mockAudit).toHaveBeenCalledTimes(1);
    const [, actorEmail, action, target, detail, client] = mockAudit.mock.calls[0] as unknown[];
    expect(actorEmail).toBe(mockSession.email);
    expect(action).toBe('license.create');
    expect(target).toBe('gms');
    expect((detail as any).after.customer).toBe('Example Corp');
    expect(client).toBeTruthy(); // joined the same transaction
  });

  it('creating needs an explicit expiry: leaving it out is refused, null means never', async () => {
    const missing = await call('PUT', '/api/v1/admin/licenses/dms', { customer: 'Example Corp' });
    expect(missing.status).toBe(400);
    expect(missing.json.error.details[0].field).toBe('expiresAt');
    const never = await call('PUT', '/api/v1/admin/licenses/dms', { customer: 'Example Corp', expiresAt: null });
    expect(never.status).toBe(201);
    expect(never.json.data.license.expiresAt).toBeNull();
    expect(never.json.data.computed.state).toBe('active');
  });

  it('updating merges, bumps the version and records before and after', async () => {
    const first = await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    const second = await call('PUT', '/api/v1/admin/licenses/gms', { maxUsers: 80, modules: null });
    expect(second.status).toBe(200);
    expect(second.json.data.action).toBe('update');
    expect(second.json.data.license).toMatchObject({ customer: 'Example Corp', maxUsers: 80, modules: null });
    expect(second.json.data.license.version).toBe(first.json.data.license.version + 1);
    const ev = (await pool.query("SELECT before, after FROM license_events WHERE id > $1 AND system = 'gms' AND action = 'update'", [baselineEventId])).rows[0];
    expect(ev.before.maxUsers).toBe(50);
    expect(ev.after.maxUsers).toBe(80);
    expect(mockAudit.mock.calls.map((c) => c[2])).toEqual(['license.create', 'license.update']);
  });

  it('a failed validation changes nothing and audits nothing', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    mockAudit.mockClear();
    const bad = await call('PUT', '/api/v1/admin/licenses/gms', { warnDays: 1000 });
    expect(bad.status).toBe(400);
    expect(mockAudit).not.toHaveBeenCalled();
    expect((await pool.query("SELECT warn_days FROM licenses WHERE system = 'gms'")).rows[0].warn_days).toBe(30);
  });

  it('the whole change rolls back when the audit write fails (nothing is half-saved)', async () => {
    mockAudit.mockRejectedValueOnce(new Error('audit chain unavailable'));
    const r = await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    expect(r.status).toBe(500);
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM licenses')).rows[0].n).toBe(0);
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM license_events WHERE id > $1', [baselineEventId])).rows[0].n).toBe(0);
  });

  it('SSO accepts no module list', async () => {
    const r = await call('PUT', '/api/v1/admin/licenses/sso', { customer: 'Example Corp', expiresAt: '2030-01-01', modules: ['visits'] });
    expect(r.status).toBe(400);
  });
});

describe('extend and revoke', () => {
  it('extend {days} counts from the later of the expiry and now, bumps the version and is recorded as "extend"', async () => {
    const created = await call('PUT', '/api/v1/admin/licenses/gms', { ...gmsLicense, expiresAt: '2030-01-01T00:00:00Z' });
    const r = await call('POST', '/api/v1/admin/licenses/gms/extend', { days: 90 });
    expect(r.status).toBe(200);
    expect(r.json.data.license.expiresAt).toBe(new Date(Date.UTC(2030, 0, 1) + 90 * DAY).toISOString());
    expect(r.json.data.license.version).toBe(created.json.data.license.version + 1);
    expect(mockAudit.mock.calls.map((c) => c[2])).toEqual(['license.create', 'license.extend']);
  });

  it('extending a lapsed licence by 30 days gives 30 days from today', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', { ...gmsLicense, expiresAt: isoDays(-100) });
    const r = await call('POST', '/api/v1/admin/licenses/gms/extend', { days: 30 });
    const got = new Date(r.json.data.license.expiresAt).getTime();
    expect(Math.abs(got - (Date.now() + 30 * DAY))).toBeLessThan(60_000);
  });

  it('extend {expiresAt} sets the date', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    const r = await call('POST', '/api/v1/admin/licenses/gms/extend', { expiresAt: '2031-06-30' });
    expect(r.json.data.license.expiresAt).toBe('2031-06-30T23:59:59.999Z');
  });

  it('refuses: nothing to extend, a perpetual licence extended by days, and bad input', async () => {
    expect((await call('POST', '/api/v1/admin/licenses/gms/extend', { days: 30 })).status).toBe(404);
    await call('PUT', '/api/v1/admin/licenses/gms', { ...gmsLicense, expiresAt: null });
    const perpetual = await call('POST', '/api/v1/admin/licenses/gms/extend', { days: 30 });
    expect(perpetual.status).toBe(409);
    expect(perpetual.json.error.code).toBe('ERR-LICENSE-PERPETUAL');
    expect((await call('POST', '/api/v1/admin/licenses/gms/extend', { days: 0 })).status).toBe(400);
    expect((await call('POST', '/api/v1/admin/licenses/gms/extend', {})).status).toBe(400);
  });

  it('revoke deletes the record, keeps the event, and a later licence continues the version numbers upward', async () => {
    const created = await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    await call('PUT', '/api/v1/admin/licenses/gms', { maxUsers: 60 });
    const before = (await call('GET', '/api/v1/admin/licenses')).json.data.systems[1].license.version;
    expect(before).toBe(created.json.data.license.version + 1);

    const gone = await call('DELETE', '/api/v1/admin/licenses/gms');
    expect(gone.status).toBe(200);
    expect((await pool.query("SELECT COUNT(*)::int AS n FROM licenses WHERE system = 'gms'")).rows[0].n).toBe(0);
    const listed = (await call('GET', '/api/v1/admin/licenses')).json.data.systems[1];
    expect(listed.license).toBeNull();
    expect(listed.events.map((e: any) => e.action)).toEqual(['revoke', 'update', 'create']);
    expect(listed.events[0].before.customer).toBe('Example Corp');
    expect(listed.events[0].after).toBeNull();

    const again = await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    expect(again.status).toBe(201);
    // revoke took version before+1, the new licence the next one: strictly higher than anything a consumer could be holding
    expect(again.json.data.license.version).toBeGreaterThan(before + 1);
    expect((await call('DELETE', '/api/v1/admin/licenses/dms')).status).toBe(404);
  });

  it('events can be read on their own', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    const r = await call('GET', '/api/v1/admin/licenses/gms/events?limit=5');
    expect(r.status).toBe(200);
    expect(r.json.data.events).toHaveLength(1);
  });
});

describe('GET /licenses/public/:system (unauthenticated)', () => {
  const noAuth = () => { state.session = false; state.platform = false; };

  it('is 404 when the system has no licence, and for an unknown system', async () => {
    noAuth();
    expect((await call('GET', '/api/v1/licenses/public/gms')).status).toBe(404);
    expect((await call('GET', '/api/v1/licenses/public/mos')).status).toBe(404);
  });

  it('serves a token signed with the OIDC signing key: header, claims, no exp, audience per system', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    noAuth();
    const r = await call('GET', '/api/v1/licenses/public/gms');
    expect(r.status).toBe(200);
    expect(typeof r.json.token).toBe('string');
    expect(r.json.data.token).toBe(r.json.token);
    const token: string = r.json.token;

    const header = decodeProtectedHeader(token);
    expect(header.alg).toBe('RS256');
    expect(header.typ).toBe('kcms-license+jwt');

    // Verify exactly as a consumer would: against the PUBLISHED public key with the header's kid.
    const keys = await loadSigningJwks();
    const jwk = keys.find((k) => k.kid === header.kid) as unknown as Record<string, string>;
    expect(jwk).toBeTruthy();
    const publicKey = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
    const { payload } = await jwtVerify(token, publicKey, { issuer: IDP_CONFIG.issuer, audience: 'license:gms', typ: 'kcms-license+jwt' });
    expect(payload).toMatchObject({
      iss: IDP_CONFIG.issuer, aud: 'license:gms', sys: 'gms', customer: 'Example Corp', expiresAt: '2030-01-01T23:59:59.999Z',
      graceDays: 14, warnDays: 30, maxUsers: 50, modules: ['visits', 'scheduling'],
    });
    expect(typeof payload.ver).toBe('number');
    expect(typeof payload.iat).toBe('number');
    expect(decodeJwt(token).exp).toBeUndefined();
    // another system's audience does not verify
    await expect(jwtVerify(token, publicKey, { audience: 'license:dms' })).rejects.toThrow();
    // nor with the private half's absence: the token holds no secret
    expect(token).not.toMatch(/"d"/);
  });

  it('a perpetual licence and "all modules" travel as null', async () => {
    await call('PUT', '/api/v1/admin/licenses/dms', { customer: 'Example Corp', expiresAt: null });
    noAuth();
    const claims = decodeJwt((await call('GET', '/api/v1/licenses/public/dms')).json.token) as any;
    expect(claims).toMatchObject({ aud: 'license:dms', sys: 'dms', expiresAt: null, maxUsers: null, modules: null });
  });

  it('a change is served at once with a higher version; the same licence answers with the same token', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    noAuth();
    const a = (await call('GET', '/api/v1/licenses/public/gms')).json.token;
    const a2 = (await call('GET', '/api/v1/licenses/public/gms')).json.token;
    expect(a2).toBe(a);
    state.platform = true; state.session = true;
    await call('POST', '/api/v1/admin/licenses/gms/extend', { days: 10 });
    noAuth();
    const b = (await call('GET', '/api/v1/licenses/public/gms')).json.token;
    expect(b).not.toBe(a);
    expect((decodeJwt(b) as any).ver).toBe((decodeJwt(a) as any).ver + 1);
  });

  it('after a revoke it is 404 again', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', gmsLicense);
    await call('DELETE', '/api/v1/admin/licenses/gms');
    noAuth();
    expect((await call('GET', '/api/v1/licenses/public/gms')).status).toBe(404);
  });
});

describe('GET /licenses/status and /license/status (SSO itself)', () => {
  it('needs a signed-in person', async () => {
    state.session = false;
    expect((await call('GET', '/api/v1/licenses/status')).status).toBe(401);
  });

  it('an IdP administrator who is not the platform administrator gets no licence information', async () => {
    state.platform = false;
    for (const p of ['/api/v1/licenses/status', '/api/v1/license/status']) {
      const r = await call('GET', p);
      expect(r.status).toBe(403);
      expect(r.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    }
  });

  it('with no licence for SSO: unconfigured, nothing read-only', async () => {
    const r = await call('GET', '/api/v1/license/status');
    expect(r.status).toBe(200);
    expect(r.json.data).toMatchObject({ system: 'sso', state: 'unconfigured', readOnly: false, customer: null, expiresAt: null, source: 'none', version: null, modules: null });
    expect(typeof r.json.data.seatsUsed).toBe('number');
  });

  it('reports each state with the contract fields', async () => {
    const cases: Array<[number, string, boolean]> = [[200, 'active', false], [10, 'expiring', false], [-3, 'grace', false], [-20, 'expired', true]];
    for (const [days, expected, readOnly] of cases) {
      await call('PUT', '/api/v1/admin/licenses/sso', { customer: 'Example Corp', expiresAt: isoDays(days), graceDays: 14, warnDays: 30, maxUsers: 100 });
      const r = await call('GET', '/api/v1/licenses/status');
      expect(r.json.data).toMatchObject({ system: 'sso', state: expected, readOnly, customer: 'Example Corp', warnDays: 30, graceDays: 14, maxUsers: 100, source: 'sso', modules: null });
      expect(typeof r.json.data.graceEndsAt).toBe('string');
      expect(typeof r.json.data.fetchedAt).toBe('string');
      expect(typeof r.json.data.version).toBe('number');
      if (expected === 'grace') expect(r.json.data.daysRemaining).toBe(-3);
    }
  });
});

describe('SSO enforces its own licence (the real guard)', () => {
  const settingsPut = () => call('PUT', '/api/v1/admin/settings/branding.productName', { value: 'x' });

  it('no licence: nothing is blocked', async () => {
    expect((await settingsPut()).json).toEqual({ reached: true });
  });

  it('active, expiring and grace: nothing is blocked', async () => {
    for (const days of [200, 10, -3]) {
      await call('PUT', '/api/v1/admin/licenses/sso', { customer: 'Example Corp', expiresAt: isoDays(days), graceDays: 14, warnDays: 30 });
      expect((await settingsPut()).json).toEqual({ reached: true });
    }
  });

  (IDP_CONFIG.licenseEnforcement === 'enforce' ? it : it.skip)('expired: admin mutations are refused with 403 LICENSE_EXPIRED, but the licence routes keep working', async () => {
    await call('PUT', '/api/v1/admin/licenses/sso', { customer: 'Example Corp', expiresAt: isoDays(-20), graceDays: 14, warnDays: 30 });
    const blocked = await settingsPut();
    expect(blocked.status).toBe(403);
    expect(blocked.json.error.code).toBe('LICENSE_EXPIRED');
    // the platform administrator can still fix it: extend, which ends the lockout at once
    const extend = await call('POST', '/api/v1/admin/licenses/sso/extend', { days: 60 });
    expect(extend.status).toBe(200);
    expect((await settingsPut()).json).toEqual({ reached: true });
    // and could equally revoke or re-save while locked
    await call('PUT', '/api/v1/admin/licenses/sso', { expiresAt: isoDays(-20) });
    expect((await settingsPut()).status).toBe(403);
    expect((await call('DELETE', '/api/v1/admin/licenses/sso')).status).toBe(200);
    expect((await settingsPut()).json).toEqual({ reached: true });
  });

  it('licences for GMS and DMS never make SSO read-only, however expired', async () => {
    await call('PUT', '/api/v1/admin/licenses/gms', { customer: 'Example Corp', expiresAt: isoDays(-400) });
    await call('PUT', '/api/v1/admin/licenses/dms', { customer: 'Example Corp', expiresAt: isoDays(-400) });
    expect((await settingsPut()).json).toEqual({ reached: true });
  });
});
