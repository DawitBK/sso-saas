/**
 * SSO's own read-only guard (src/licenses/guard.ts). Driven over real HTTP with stubbed state, so it needs no database.
 *
 * Proves: while SSO's licence is expired every non-allowlisted POST/PUT/PATCH/DELETE answers 403 LICENSE_EXPIRED; safe methods and EVERY allowlist
 * entry keep working (one test per entry, because the allowlist is what keeps sign-in alive); nothing happens when the licence is not expired,
 * in warn or off mode, or when the state cannot be read.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import express from 'express';
import { LICENSE_EXPIRED_MESSAGE, READ_ONLY_ALLOWLIST, isAllowlisted, licenseReadOnlyGuard, type GuardDeps } from '../src/licenses/guard.js';

const deps: GuardDeps & { state: { expired: boolean; unlicensed: boolean; mode: 'enforce' | 'warn' | 'off'; throws: boolean } } = {
  state: { expired: true, unlicensed: false, mode: 'enforce', throws: false },
  mode() { return this.state.mode; },
  async expired() {
    if (this.state.throws) throw new Error('database down');
    return this.state.expired;
  },
  async unlicensed() {
    if (this.state.throws) throw new Error('database down');
    return this.state.unlicensed;
  },
};

let server: http.Server;
let base = '';

beforeAll(async () => {
  const app = express();
  app.use(licenseReadOnlyGuard({ mode: () => deps.mode(), expired: () => deps.expired(), unlicensed: () => deps.unlicensed() }));
  app.use((_req, res) => res.json({ reached: true }));
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => { await new Promise<void>((r) => server.close(() => r())); });
beforeEach(() => { deps.state.expired = true; deps.state.unlicensed = false; deps.state.mode = 'enforce'; deps.state.throws = false; });

async function send(method: string, path: string) {
  const res = await fetch(`${base}${path}`, { method, headers: { 'content-type': 'application/json' }, body: ['GET', 'HEAD'].includes(method) ? undefined : '{}' });
  const json = method === 'HEAD' ? null : ((await res.json()) as any);
  return { status: res.status, json };
}

describe('while the licence is expired (enforce)', () => {
  it.each([
    ['POST', '/api/v1/admin/users'],
    ['PUT', '/api/v1/admin/users/abc'],
    ['POST', '/api/v1/admin/users/abc/toggle-active'],
    ['POST', '/api/v1/admin/users/bulk'],
    ['POST', '/api/v1/admin/groups/entitlements'],
    ['PUT', '/api/v1/admin/settings/branding.productName'],
    ['DELETE', '/api/v1/admin/settings/branding.productName'],
    ['PUT', '/api/v1/admin/clients/edams/uris'],
    ['POST', '/api/v1/admin/sessions/revoke'],
    ['POST', '/api/v1/admin/password-reset-requests/5/dismiss'],
    ['POST', '/api/v1/admin/audit/chain-acknowledgements'],
    ['PATCH', '/api/v1/admin/anything'],
    ['POST', '/portalx'],
    ['POST', '/something-new'],
  ])('refuses %s %s with 403 LICENSE_EXPIRED and the contract message', async (method, path) => {
    const r = await send(method, path);
    expect(r.status).toBe(403);
    expect(r.json.error).toEqual({ code: 'LICENSE_EXPIRED', message: LICENSE_EXPIRED_MESSAGE });
    expect(r.json.error.message).toBe('The licence has expired; the system is read-only. Contact your administrator.');
  });

  it.each(['GET', 'HEAD', 'OPTIONS'])('lets %s through anywhere (safe methods always pass)', async (method) => {
    const r = await fetch(`${base}/api/v1/admin/users`, { method });
    expect(r.status).toBe(200);
  });
});

describe('the allowlist keeps working while expired: one test per entry', () => {
  it.each([...READ_ONLY_ALLOWLIST])('%s (and anything beneath it)', async (entry) => {
    for (const method of ['POST', 'PUT', 'DELETE']) {
      expect((await send(method, entry)).json).toEqual({ reached: true });
      expect((await send(method, `${entry}/x`)).json).toEqual({ reached: true });
    }
  });

  it.each([
    // sign-in
    ['POST', '/interaction/abc123/login'],
    ['POST', '/interaction/abc123/totp'],
    ['POST', '/interaction/abc123/password'],
    ['POST', '/interaction/abc123/confirm'],
    ['POST', '/interaction/abc123/abort'],
    // OIDC and tokens
    ['POST', '/token'],
    ['POST', '/token/introspection'],
    ['POST', '/token/revocation'],
    ['POST', '/authorize'],
    ['POST', '/me'],
    ['POST', '/session/end/confirm'],
    // the portal and its own security page, the GMS bridge
    ['POST', '/portal/login'],
    ['POST', '/portal/logout'],
    ['POST', '/portal/security/password/change'],
    ['POST', '/portal/security/totp/confirm'],
    ['POST', '/bridge/gms/start'],
    ['POST', '/api/v1/auth/password-reset-request'],
    ['POST', '/api/v1/portal/anything'],
    // health
    ['POST', '/health'],
    ['POST', '/health/ready'],
    ['POST', '/api/v1/health/ready'],
    // licences: the platform administrator must always be able to manage them
    ['PUT', '/api/v1/admin/licenses/gms'],
    ['PUT', '/api/v1/admin/licenses/sso'],
    ['POST', '/api/v1/admin/licenses/dms/extend'],
    ['DELETE', '/api/v1/admin/licenses/gms'],
    ['GET', '/api/v1/licenses/public/gms'],
    ['GET', '/api/v1/license/status'],
    // GMS managing its own role grants, and signing-key emergencies
    ['PUT', '/internal/gms/users/a%40b.co/roles'],
    ['PUT', '/api/v1/internal/gms/users/a%40b.co/roles'],
    ['POST', '/api/v1/admin/keys/generate'],
    ['POST', '/api/v1/admin/keys/abc/retire'],
    // the owner's verification sequence: it is how a licence is saved in production, so it must work while a licence is missing or expired
    ['POST', '/api/v1/owner/verification/start'],
    ['POST', '/api/v1/owner/verification/answer-questions'],
    ['POST', '/api/v1/owner/verification/send-email-code'],
    ['POST', '/api/v1/owner/verification/verify-email-code'],
    ['POST', '/api/v1/owner/verification/verify-recovery-code'],
    ['POST', '/api/v1/owner/verification/verify-totp'],
    ['POST', '/api/v1/owner/verification/finish'],
  ])('real route %s %s passes', async (method, path) => {
    expect((await send(method, path)).json).toEqual({ reached: true });
  });
});

describe('when it must do nothing', () => {
  it('the licence is not expired', async () => {
    deps.state.expired = false;
    expect((await send('POST', '/api/v1/admin/users')).json).toEqual({ reached: true });
  });
  it('LICENSE_ENFORCEMENT=warn never blocks', async () => {
    deps.state.mode = 'warn';
    expect((await send('POST', '/api/v1/admin/users')).json).toEqual({ reached: true });
  });
  it('LICENSE_ENFORCEMENT=off never blocks', async () => {
    deps.state.mode = 'off';
    expect((await send('POST', '/api/v1/admin/users')).json).toEqual({ reached: true });
  });
  it('the state cannot be read: it fails open', async () => {
    deps.state.throws = true;
    expect((await send('POST', '/api/v1/admin/users')).json).toEqual({ reached: true });
  });
});

describe('isAllowlisted', () => {
  it('matches whole path segments only', () => {
    expect(isAllowlisted('/portal')).toBe(true);
    expect(isAllowlisted('/portal/')).toBe(true);
    expect(isAllowlisted('/portal/login')).toBe(true);
    expect(isAllowlisted('/portalx')).toBe(false);
    expect(isAllowlisted('/token')).toBe(true);
    expect(isAllowlisted('/tokens')).toBe(false);
    expect(isAllowlisted('/api/v1/admin/licenses')).toBe(true);
    expect(isAllowlisted('/api/v1/admin/licensesx')).toBe(false);
    expect(isAllowlisted('/api/v1/owner/verification/start')).toBe(true);
    expect(isAllowlisted('/api/v1/owner/verificationx')).toBe(false);
    expect(isAllowlisted('/api/v1/admin/users')).toBe(false);
    expect(isAllowlisted('/')).toBe(false);
  });
});

describe('LICENSE_REQUIRED and no licence for SSO (section 9)', () => {
  beforeEach(() => { deps.state.expired = false; deps.state.unlicensed = true; });

  it.each([
    ['GET', '/api/v1/admin/users'],
    ['POST', '/api/v1/admin/users'],
    ['GET', '/api/v1/admin/settings'],
  ])('%s %s answers 403 LICENSE_REQUIRED', async (method, path) => {
    const r = await send(method, path);
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('LICENSE_REQUIRED');
    expect(r.json.error.message).toBe('This system is not licensed. Contact your administrator.');
  });

  it.each(READ_ONLY_ALLOWLIST.map((p) => ['POST', p]))('the allowlist still works: %s %s', async (method, path) => {
    // /authorize is checked separately below (only the portal client may use it while unlicensed)
    if (path === '/authorize') return;
    const r = await send(method, path);
    expect(r.status).toBe(200);
  });

  it('sign-in for the portal client keeps working, for any other relying party it is refused', async () => {
    expect((await send('GET', '/authorize?client_id=portal')).status).toBe(200);
    const other = await send('GET', '/authorize?client_id=edams');
    expect(other.status).toBe(403);
    expect(other.json.error.code).toBe('LICENSE_REQUIRED');
  });

  it('warn only logs; off does nothing', async () => {
    deps.state.mode = 'warn';
    expect((await send('GET', '/api/v1/admin/users')).status).toBe(200);
    deps.state.mode = 'off';
    expect((await send('GET', '/api/v1/admin/users')).status).toBe(200);
  });

  it('a failure reading the licence lets the request through (fail open, nothing deleted)', async () => {
    deps.state.throws = true;
    expect((await send('GET', '/api/v1/admin/users')).status).toBe(200);
  });

  it('licensed again: everything is served', async () => {
    deps.state.unlicensed = false;
    expect((await send('GET', '/api/v1/admin/users')).status).toBe(200);
  });
});
