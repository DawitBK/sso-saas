/**
 * Every owner-only operation is really behind the gate (OWNER_VERIFICATION_REQUIRED true), plus migration 027 up and down.
 *
 *   1. Static: every operation in owner/registry.ts that SSO performs is named by a route in src/, and every operation key a route names is in the registry.
 *   2. Wired: the REAL licences router and the REAL settings router, on a scratch database (idp_p4_scratch2), refuse without a ticket, accept the right one
 *      once, refuse a ticket for another operation or target, and leave a non-owner to the route's own refusal. Platform settings need a ticket; the
 *      settings an ordinary administrator may change do not.
 *   3. Migration 027's rollback removes exactly its own tables and the migration can be applied again.
 *
 * Mocked: the portal session lookup, the platform-administrator check, the admin audit writer, the admin sign-in gate and the mail transport.
 * Every secret here is generated at run time.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

const state = { platform: true };
const SESSIONS: Record<string, { accountId: string; name: string; email: string; groups: string[]; createdAt: number }> = {};

jest.mock('../src/db/pool.js', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pgLib = require('pg');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { IDP_CONFIG } = require('../src/config.js');
  const u = new URL(IDP_CONFIG.databaseUrl);
  u.pathname = '/idp_p4_scratch2';
  const pool = new pgLib.Pool({ connectionString: u.toString(), max: 8 });
  return { pool, query: (...a: unknown[]) => pool.query(...a) };
});
jest.mock('../src/portal/session.js', () => ({ getPortalSession: async (key: string) => SESSIONS[key] }));
jest.mock('../src/auth/platform-admin.js', () => ({
  ...jest.requireActual('../src/auth/platform-admin.js'),
  isPlatformAdminSession: async (s?: { accountId?: string }) => state.platform && s?.accountId === 'owner-account',
}));
const mockAudit = jest.fn(async (..._a: unknown[]) => undefined);
jest.mock('../src/admin/audit.js', () => ({ writeAudit: (...a: unknown[]) => mockAudit(...a), recentAudit: jest.fn(), countAuditRows: jest.fn(), verifyAuditChain: jest.fn() }));
jest.mock('../src/admin/requireAdmin.js', () => {
  const gate = () => (req: { headers: { cookie?: string }; adminSession?: unknown }, _res: unknown, next: () => void) => {
    const key = /idp_portal=([^;]+)/.exec(req.headers.cookie ?? '')?.[1] ?? '';
    req.adminSession = SESSIONS[key];
    next();
  };
  return { requireAdminJson: gate, getPortalSessionFromRequest: async () => null };
});

import express from 'express';
import { ADMIN_API_CSRF_COOKIE } from '../src/api/v1/admin.router.js';
import { licensesAdminRouter } from '../src/api/v1/licenses.router.js';
import { settingsAdminRouter } from '../src/api/v1/settings.router.js';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { answerQuestions, finishChallenge, sendEmailCode, startChallenge, verifyEmailCode, verifyTotpStep } from '../src/owner/challenge.js';
import { enrolOwner } from '../src/owner/enrol.js';
import { __setOwnerMailerForTests } from '../src/owner/mailer.js';
import { __setKdfParamsForTests } from '../src/owner/questions.js';
import { OWNER_OPERATIONS } from '../src/owner/registry.js';
import { __setOwnerRuntimeForTests } from '../src/owner/runtime.js';
import { createKeyFile, loadStoreKeys } from '../src/owner/seal.js';
import { sessionHashOf } from '../src/owner/session.js';
import { __setSnapshotForTests } from '../src/settings/store.js';
import { createScratchDb, dropScratchDb, scratchUrl, tempKeyFilePath, throwaway, totpCode } from './helpers/ownerHelpers.js';

const SCRATCH = 'idp_p4_scratch2';
const OWNER = 'owner-account';
const CSRF = 'a'.repeat(48);
const SMTP = { host: 'smtp.test.invalid', port: 587, secure: false, user: 'mailer', pass: 'unused', from: 'noreply@test.invalid' };

let server: http.Server;
let base = '';
let keyFile = '';
let enrolled: { answers: string[]; totpSecret: string };
const sent: Array<{ text: string }> = [];
const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

async function ticketFor(operation: string, target?: string): Promise<string> {
  const ctx = { accountId: OWNER, sessionHash: sessionHashOf('sessOwner') };
  const c = await startChallenge(ctx, { operation, target });
  await answerQuestions(ctx, c.challengeId, enrolled.answers);
  await sendEmailCode(ctx, c.challengeId);
  await verifyEmailCode(ctx, c.challengeId, /code is: (\d+)/.exec(sent[sent.length - 1]!.text)![1]!);
  await pool.query('UPDATE owner_verification_state SET totp_last_step = 0');
  await verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret));
  return (await finishChallenge(ctx, c.challengeId)).ticket;
}

async function call(method: string, p: string, opts: { body?: Record<string, unknown>; ticket?: string; session?: string } = {}) {
  const res = await fetch(`${base}${p}`, {
    method,
    headers: {
      'content-type': 'application/json',
      cookie: `idp_portal=${opts.session ?? 'sessOwner'}; ${ADMIN_API_CSRF_COOKIE}=${CSRF}`,
      ...(opts.ticket ? { 'x-owner-authorisation': opts.ticket } : {}),
    },
    body: method === 'GET' ? undefined : JSON.stringify({ ...(opts.body ?? {}), csrf: CSRF }),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

const gms = { customer: 'Example Corp', expiresAt: '2030-01-01', graceDays: 14, warnDays: 30, maxUsers: 50, modules: null };

beforeAll(async () => {
  __setKdfParamsForTests({ logN: 10, r: 8, p: 1 });
  await createScratchDb(IDP_CONFIG.databaseUrl, SCRATCH);
  keyFile = tempKeyFilePath();
  const keys = createKeyFile(keyFile);
  __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: SMTP });
  SESSIONS.sessOwner = { accountId: OWNER, name: 'Owner', email: 'owner@test.invalid', groups: [IDP_CONFIG.adminGroup], createdAt: 1 };
  SESSIONS.sessAdmin = { accountId: 'someone-else', name: 'Admin', email: 'admin@test.invalid', groups: [IDP_CONFIG.adminGroup], createdAt: 2 };
  __setOwnerMailerForTests({ async send(m) { sent.push(m); } });
  const answers = [throwaway('a'), throwaway('b'), throwaway('c')];
  const totpSecret = (await import('../src/auth/totp.js')).generateTotpSecret();
  await enrolOwner({
    keys: loadStoreKeys(keyFile),
    accountId: OWNER,
    questions: answers.map((answer, i) => ({ prompt: `Question ${i + 1}`, answer })),
    emailAddress: `${throwaway('owner')}@mail.test.invalid`,
    totpSecret,
  });
  void keys;
  enrolled = { answers, totpSecret };

  const app = express();
  app.use('/api/v1/admin/licenses', licensesAdminRouter());
  app.use('/api/v1/admin/settings', settingsAdminRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 60_000);

beforeEach(async () => {
  await pool.query('DELETE FROM licenses');
  await pool.query('DELETE FROM owner_verification_challenges');
  await pool.query('UPDATE owner_verification_state SET consecutive_failures = 0, lockout_level = 0, locked_until = NULL');
  mockAudit.mockClear();
  state.platform = true;
  __setSnapshotForTests({});
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
  await dropScratchDb(IDP_CONFIG.databaseUrl, SCRATCH);
  try {
    fs.rmSync(path.dirname(keyFile), { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

describe('every owner-only operation is behind the gate (static)', () => {
  const SRC = path.resolve(process.cwd(), 'src');
  const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith('.ts') ? [path.join(dir, e.name)] : []));
  const used = new Set<string>();
  for (const f of walk(SRC)) {
    if (f.includes(`${path.sep}owner${path.sep}`)) continue; // the module itself defines, it does not enforce
    const text = fs.readFileSync(f, 'utf8');
    for (const m of text.matchAll(/(?:requireOwnerAuthorisation|authoriseOwnerOperation)\(\s*(?:req,\s*res,\s*)?['"]([a-z_.]+)['"]/g)) used.add(m[1] as string);
  }

  it('every operation SSO performs is enforced by a route', () => {
    const missing = OWNER_OPERATIONS.filter((o) => o.audience === 'sso' && !o.cli && !used.has(o.key)).map((o) => o.key);
    expect(missing).toEqual([]);
  });

  it('every operation a route names is in the registry', () => {
    const known = new Set(OWNER_OPERATIONS.map((o) => o.key));
    expect([...used].filter((k) => !known.has(k))).toEqual([]);
  });
});

describe('the real licences router', () => {
  it('saving without a ticket is refused and nothing is written', async () => {
    const r = await call('PUT', '/api/v1/admin/licenses/gms', { body: gms });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('OWNER_AUTHORISATION_REQUIRED');
    expect(r.json.error.operation).toBe('license.save');
    expect(r.json.error.target).toBe('gms');
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM licenses')).rows[0].n).toBe(0);
  });

  it('the right ticket saves once; the same ticket again, or a ticket for another operation or system, does not', async () => {
    const ticket = await ticketFor('license.save', 'gms');
    expect((await call('PUT', '/api/v1/admin/licenses/dms', { body: gms, ticket })).json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    expect((await call('POST', '/api/v1/admin/licenses/gms/extend', { body: { days: 10 }, ticket })).json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    const saved = await call('PUT', '/api/v1/admin/licenses/gms', { body: gms, ticket });
    expect(saved.status).toBe(201);
    await settle();
    const replay = await call('PUT', '/api/v1/admin/licenses/gms', { body: gms, ticket });
    expect(replay.status).toBe(403);
    expect(replay.json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    // the ticket for the extension and the removal are separate operations
    const ext = await ticketFor('license.extend', 'gms');
    expect((await call('POST', '/api/v1/admin/licenses/gms/extend', { body: { days: 10 }, ticket: ext })).status).toBe(200);
    expect((await call('DELETE', '/api/v1/admin/licenses/gms', { ticket: await ticketFor('license.save', 'gms') })).json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    expect((await call('DELETE', '/api/v1/admin/licenses/gms', { ticket: await ticketFor('license.revoke', 'gms') })).status).toBe(200);
    await settle();
  });

  it('a validation error does not cost the ticket', async () => {
    const ticket = await ticketFor('license.save', 'gms');
    const bad = await call('PUT', '/api/v1/admin/licenses/gms', { body: { ...gms, graceDays: -5 }, ticket });
    expect(bad.status).toBeGreaterThanOrEqual(400);
    expect(bad.status).toBeLessThan(500);
    await settle();
    expect((await call('PUT', '/api/v1/admin/licenses/gms', { body: gms, ticket })).status).toBe(201);
  });

  it('an administrator who is not the platform administrator gets the route\'s own refusal, unchanged', async () => {
    const r = await call('PUT', '/api/v1/admin/licenses/gms', { body: gms, session: 'sessAdmin' });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
  });

  it('reading is not gated', async () => {
    expect((await call('GET', '/api/v1/admin/licenses')).status).toBe(200);
  });
});

describe('the real settings router', () => {
  it('a platform-owned setting needs a ticket bound to that setting; an administrator-owned one does not', async () => {
    const none = await call('PUT', '/api/v1/admin/settings/lockout.threshold', { body: { value: 6 } });
    expect(none.status).toBe(403);
    expect(none.json.error.code).toBe('OWNER_AUTHORISATION_REQUIRED');
    expect(none.json.error.operation).toBe('setting.change');
    expect(none.json.error.target).toBe('lockout.threshold');

    const wrong = await ticketFor('setting.change', 'lockout.minutes');
    expect((await call('PUT', '/api/v1/admin/settings/lockout.threshold', { body: { value: 6 }, ticket: wrong })).json.error.code).toBe('OWNER_AUTHORISATION_INVALID');

    const ticket = await ticketFor('setting.change', 'lockout.threshold');
    const ok = await call('PUT', '/api/v1/admin/settings/lockout.threshold', { body: { value: 6 }, ticket });
    expect(ok.status).toBe(200);
    await settle();
    expect((await call('PUT', '/api/v1/admin/settings/lockout.threshold', { body: { value: 7 }, ticket })).status).toBe(403);

    // an ordinary administrator-owned setting: no ticket, no owner (the existing behaviour, unchanged)
    state.platform = false;
    const plain = await call('PUT', '/api/v1/admin/settings/branding.tagline', { body: { value: 'Hello' }, session: 'sessAdmin' });
    expect(plain.status).toBe(200);
    // and a platform-owned one by a non-owner is the route's own refusal
    const refused = await call('PUT', '/api/v1/admin/settings/lockout.threshold', { body: { value: 6 }, session: 'sessAdmin' });
    expect(refused.status).toBe(403);
    expect(refused.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
  });

  it('resetting a platform-owned setting is gated the same way', async () => {
    expect((await call('DELETE', '/api/v1/admin/settings/lockout.threshold')).json.error.code).toBe('OWNER_AUTHORISATION_REQUIRED');
  });
});

describe('migration 027', () => {
  it('its rollback removes only its own tables, and it can be applied again', async () => {
    const url = scratchUrl(IDP_CONFIG.databaseUrl, SCRATCH);
    const c = new pg.Client({ connectionString: url });
    await c.connect();
    try {
      const names = async () => (await c.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE 'owner\\_%' ORDER BY 1")).rows.map((r) => r.table_name);
      const before = await names();
      expect(before).toEqual([
        'owner_recovery_codes_used',
        'owner_verification_audit',
        'owner_verification_challenges',
        'owner_verification_state',
        'owner_verification_store',
        'owner_verification_tickets',
      ]);
      const totalBefore = (await c.query("SELECT COUNT(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public'")).rows[0].n;
      const dir = path.resolve(process.cwd(), 'migrations');
      await c.query(fs.readFileSync(path.join(dir, '027_owner_verification.down.sql'), 'utf8'));
      expect(await names()).toEqual([]);
      expect((await c.query("SELECT COUNT(*)::int AS n FROM information_schema.tables WHERE table_schema = 'public'")).rows[0].n).toBe(totalBefore - before.length);
      await c.query(fs.readFileSync(path.join(dir, '027_owner_verification.sql'), 'utf8'));
      expect(await names()).toEqual(before);
    } finally {
      await c.end();
    }
  });
});
