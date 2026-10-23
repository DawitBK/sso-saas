/**
 * The incident lock and SSO's read-only containment (ops/incidentLock.ts, ops/incidentGuard.ts). Driven over real HTTP with a real temporary lock file.
 *
 * Proves: no lock file (or the feature off) changes nothing; with a lock file every non-allowlisted POST/PUT/PATCH/DELETE answers 403 INCIDENT_READ_ONLY;
 * reads and EVERY licence-allowlist entry keep working (sign-in, health, licence routes); the lock is cached for about three seconds; removing the file lifts
 * the lock; a lock file with junk content still locks; an unreadable path fails open; the lock body holds no secret and is never overwritten.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import express from 'express';
import { READ_ONLY_ALLOWLIST } from '../src/licenses/guard.js';
import { INCIDENT_EXTRA_ALLOWLIST, incidentReadOnlyGuard } from '../src/ops/incidentGuard.js';
import { activeIncidentLock, readIncidentLock, resetIncidentLockCache, setMemoryIncidentLock, writeIncidentLock } from '../src/ops/incidentLock.js';

let dir = '';
let lockFile = '';
let server: http.Server;
let base = '';

beforeAll(async () => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-guard-'));
  lockFile = path.join(dir, 'incident.lock');
  const app = express();
  app.use(incidentReadOnlyGuard({ lock: () => activeIncidentLock(lockFile) }));
  app.use((_req, res) => res.json({ reached: true }));
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  fs.rmSync(dir, { recursive: true, force: true });
});
beforeEach(() => {
  fs.rmSync(lockFile, { force: true });
  resetIncidentLockCache();
});

async function send(method: string, p: string) {
  const res = await fetch(`${base}${p}`, { method, headers: { 'content-type': 'application/json' }, body: ['GET', 'HEAD'].includes(method) ? undefined : '{}' });
  return { status: res.status, json: method === 'HEAD' ? null : ((await res.json()) as any) };
}

describe('with no lock', () => {
  it('lets every method through', async () => {
    for (const m of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) expect((await send(m, '/api/v1/admin/users')).status).toBe(200);
  });
  it('treats an unset path as the feature being off', () => {
    expect(readIncidentLock('')).toBeNull();
    expect(readIncidentLock(undefined)).toBeNull();
  });
});

describe('with a lock file', () => {
  beforeEach(() => {
    expect(writeIncidentLock(lockFile, { reason: 'audit_chain_broken', kind: 'audit_chain_broken' })).toBe(true);
    resetIncidentLockCache();
  });

  it.each([
    ['POST', '/api/v1/admin/users'],
    ['PUT', '/api/v1/admin/users/abc'],
    ['PATCH', '/api/v1/admin/anything'],
    ['DELETE', '/api/v1/admin/settings/branding.productName'],
    ['POST', '/api/v1/admin/sessions/revoke'],
    ['POST', '/portalx'],
  ])('refuses %s %s with 403 INCIDENT_READ_ONLY', async (method, p) => {
    const r = await send(method, p);
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('INCIDENT_READ_ONLY');
  });

  it('keeps reads working', async () => {
    for (const p of ['/api/v1/admin/users', '/portal', '/api/v1/health']) expect((await send('GET', p)).status).toBe(200);
    expect((await send('HEAD', '/api/v1/admin/users')).status).toBe(200);
  });

  it.each(READ_ONLY_ALLOWLIST.map((p) => [p]))('keeps %s working for POST (sign-in, health and licence routes must survive containment)', async (p) => {
    expect((await send('POST', p)).status).toBe(200);
    expect((await send('POST', `${p}/sub`)).status).toBe(200);
  });

  it.each(INCIDENT_EXTRA_ALLOWLIST.map((p) => [p]))('keeps the owner verification sequence (%s) working, so the owner can still verify while locked', async (p) => {
    for (const sub of ['/start', '/answer', '/code', '/recovery']) expect((await send('POST', `${p}${sub}`)).status).toBe(200);
  });

  describe('the audit-chain acknowledgement (the way out of a lock caused by a broken audit log)', () => {
    const ACK = '/api/v1/admin/audit/chain-acknowledgements';

    it('is on the extra allowlist, as an exact path', () => {
      expect(INCIDENT_EXTRA_ALLOWLIST).toContain(ACK);
      expect(INCIDENT_EXTRA_ALLOWLIST.filter((p) => p.includes('audit'))).toEqual([ACK]);
    });
    it('lets POST through while locked', async () => {
      expect((await send('POST', ACK)).status).toBe(200);
      expect((await send('POST', `${ACK}/`)).status).toBe(200); // a trailing slash is the same route
    });
    it.each([
      ['POST', '/api/v1/admin/audit/chain-acknowledgementsx'],
      ['POST', '/api/v1/admin/audit/chain-acknowledgements-old'],
      ['POST', '/api/v1/admin/audit'],
      ['POST', '/api/v1/admin/audit/verify'],
      ['POST', '/api/v1/admin/audit/export'],
      ['POST', '/api/v1/admin/x/audit/chain-acknowledgements'],
      ['POST', '/api/v1/admin/audit/chain-acknowledgement'],
      ['DELETE', '/api/v1/admin/audit/chain-acknowledgementsx'],
    ])('still refuses the look-alike %s %s', async (method, p) => {
      const r = await send(method, p);
      expect(r.status).toBe(403);
      expect(r.json.error.code).toBe('INCIDENT_READ_ONLY');
    });
    it('still refuses every other admin change while locked, and keeps GET working', async () => {
      for (const [m, p] of [['POST', '/api/v1/admin/users'], ['PUT', '/api/v1/admin/settings'], ['POST', '/api/v1/admin/groups'], ['POST', '/api/v1/admin/clients']] as const) {
        expect((await send(m, p)).status).toBe(403);
      }
      expect((await send('GET', ACK)).status).toBe(200);
    });
    it('does not lift the lock: the lock is still in force after the acknowledgement route was reached', async () => {
      expect((await send('POST', ACK)).status).toBe(200);
      expect(activeIncidentLock(lockFile)).not.toBeNull();
      expect((await send('POST', '/api/v1/admin/users')).status).toBe(403);
    });
  });

  it('still refuses the owner-only operations themselves unless they are on the licence list (a key rotation is, a tenant creation is not)', async () => {
    expect((await send('POST', '/api/v1/admin/keys/rotate')).status).toBe(200);
    expect((await send('POST', '/api/v1/owner/other')).status).toBe(403);
  });

  it('lifts when the file is removed (after the cache window)', async () => {
    expect((await send('POST', '/api/v1/admin/users')).status).toBe(403);
    fs.rmSync(lockFile);
    resetIncidentLockCache(); // stands in for the three seconds passing
    expect((await send('POST', '/api/v1/admin/users')).status).toBe(200);
  });

  it('caches the answer for about three seconds', () => {
    const t0 = Date.now();
    expect(readIncidentLock(lockFile, t0)).not.toBeNull();
    fs.rmSync(lockFile);
    expect(readIncidentLock(lockFile, t0 + 2000)).not.toBeNull(); // still cached
    expect(readIncidentLock(lockFile, t0 + 3500)).toBeNull(); // expired
  });
});

describe('the lock file', () => {
  it('holds only at, reason and kind, and is never overwritten', () => {
    expect(writeIncidentLock(lockFile, { reason: 'first', kind: 'k1' })).toBe(true);
    expect(writeIncidentLock(lockFile, { reason: 'second', kind: 'k2' })).toBe(false);
    const body = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
    expect(Object.keys(body).sort()).toEqual(['at', 'kind', 'reason']);
    expect(body.reason).toBe('first');
  });
  it('still locks when someone created it by hand with any content', () => {
    fs.writeFileSync(lockFile, 'not json at all');
    expect(readIncidentLock(lockFile)).toEqual({ at: null, reason: null, kind: null });
  });
  it('fails open when the path cannot be inspected (a file used as a directory)', () => {
    fs.writeFileSync(lockFile, '{}');
    expect(readIncidentLock(path.join(lockFile, 'nested', 'incident.lock'))).toBeNull();
  });
  it('an in-process lock applies when no file is configured, and the file wins when both exist', () => {
    expect(activeIncidentLock('')).toBeNull();
    setMemoryIncidentLock({ reason: 'memory', kind: 'm' });
    expect(activeIncidentLock('')?.reason).toBe('memory');
    fs.writeFileSync(lockFile, JSON.stringify({ at: 'x', reason: 'file', kind: 'f' }));
    expect(activeIncidentLock(lockFile)?.reason).toBe('file');
  });
});

describe('the guard itself', () => {
  it('never throws: a failing lock lookup lets the request through', async () => {
    const app = express();
    app.use(incidentReadOnlyGuard({ lock: () => { throw new Error('boom'); } }));
    app.use((_req, res) => res.json({ reached: true }));
    const s = http.createServer(app);
    await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
    const res = await fetch(`http://127.0.0.1:${(s.address() as AddressInfo).port}/x`, { method: 'POST' });
    expect(res.status).toBe(200);
    await new Promise<void>((r) => s.close(() => r()));
  });
});
