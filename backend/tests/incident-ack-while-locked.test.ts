/**
 * The way out of a lock caused by a broken audit log, end to end, on a SCRATCH database (idp_ackdl_scratch_<pid>_<random>, created, migrated and dropped here;
 * never idp, idpprod or any shared database).
 *
 * Found on the mirror 2026-10-21: SSO's incident response treats "the audit log no longer verifies" as critical and, in `contain` mode, locks the platform
 * read-only; the acknowledgement of a known, explained break (POST /api/v1/admin/audit/chain-acknowledgements) is the only way to explain an old break, and it
 * used to be refused by that very lock. Proves, with the REAL audit writer and verifier, the REAL incident handler (contain mode, real lock file), the REAL
 * incident guard, the REAL admin-mutations router and the REAL owner-authorisation gate (a ticket from the real verification sequence):
 *   1. two broken audit entries are found by the scheduled check and lock the platform (every other change answers 403 INCIDENT_READ_ONLY);
 *   2. the acknowledgement route is reached while locked, and is still refused without the owner's authorisation, for a non-owner and without CSRF;
 *   3. acknowledging the first break (one stays open) records NO new incident (the mirror's incident #3), acknowledging the second makes the chain verify;
 *   4. the acknowledgement entries themselves do not break the chain, and later checks raise nothing;
 *   5. the lock is still in force after the chain is clean: only the terminal's `tamper.cjs clear` (here: removing the file) lifts it.
 *
 * Mocked: the portal session lookup, the platform-administrator check (the real vault does not exist in tests), the admin sign-in gate and the mail transport.
 * Every secret here is generated at run time.
 */
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import type { AddressInfo } from 'node:net';
import pg from 'pg';

const state = { platform: true };
const SESSIONS: Record<string, { accountId: string; name: string; email: string; groups: string[]; createdAt: number }> = {};
const mockScratch: { pool: pg.Pool | null } = { pool: null };

jest.mock('../src/db/pool.js', () => {
  const forward = (prop: string | symbol) => {
    const target = mockScratch.pool as unknown as Record<string | symbol, unknown> | null;
    if (!target) throw new Error('scratch pool is not ready (beforeAll has not run)');
    const value = target[prop];
    return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
  };
  return { pool: new Proxy({}, { get: (_t, prop) => forward(prop) }) };
});
jest.mock('../src/portal/session.js', () => ({ getPortalSession: async (key: string) => SESSIONS[key] }));
jest.mock('../src/auth/platform-admin.js', () => ({
  ...jest.requireActual('../src/auth/platform-admin.js'),
  isPlatformAdminSession: async (s?: { accountId?: string }) => state.platform && s?.accountId === 'owner-account',
}));
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
import { adminMutationsRouter } from '../src/api/v1/admin-mutations.router.js';
import { verifyAuditChain, writeAudit } from '../src/admin/audit.js';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { createIncidentHandler, defaultDeps, resetIncidentState } from '../src/ops/incidents.js';
import { incidentReadOnlyGuard } from '../src/ops/incidentGuard.js';
import { activeIncidentLock, resetIncidentLockCache, writeIncidentLock } from '../src/ops/incidentLock.js';
import { resetAuditChainState, runAuditChainCheck } from '../src/ops/auditChain.js';
import { onSecurityEvent } from '../src/ops/securityEvents.js';
import { answerQuestions, finishChallenge, sendEmailCode, startChallenge, verifyEmailCode, verifyTotpStep } from '../src/owner/challenge.js';
import { enrolOwner } from '../src/owner/enrol.js';
import { __setOwnerMailerForTests } from '../src/owner/mailer.js';
import { __setKdfParamsForTests } from '../src/owner/questions.js';
import { __setOwnerRuntimeForTests } from '../src/owner/runtime.js';
import { createKeyFile, loadStoreKeys } from '../src/owner/seal.js';
import { sessionHashOf } from '../src/owner/session.js';
import { tempKeyFilePath, throwaway, totpCode } from './helpers/ownerHelpers.js';

const scratchName = `idp_ackdl_scratch_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const scratchUrl = (() => { const u = new URL(IDP_CONFIG.databaseUrl); u.pathname = `/${scratchName}`; return u.toString(); })();
const MIGRATIONS = path.join(__dirname, '..', 'migrations');
const OWNER = 'owner-account';
const CSRF = 'b'.repeat(48);
const REASON = 'Written with the old v1 hash in July; known and reviewed by the owner.';
const SMTP = { host: 'smtp.test.invalid', port: 587, secure: false, user: 'mailer', pass: 'unused', from: 'noreply@test.invalid' };
const ACK = '/api/v1/admin/audit/chain-acknowledgements';
const REQ = { ip: '', get: () => '' } as never;

let server: http.Server;
let base = '';
let dir = '';
let lockFile = '';
let keyFile = '';
let unsubscribe: () => void = () => undefined;
let enrolled: { answers: string[]; totpSecret: string };
const sent: Array<{ text: string }> = [];
const settle = (ms = 300) => new Promise((r) => setTimeout(r, ms));

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

async function call(method: string, p: string, opts: { body?: Record<string, unknown>; ticket?: string; session?: string; csrf?: boolean } = {}) {
  const res = await fetch(`${base}${p}`, {
    method,
    headers: {
      'content-type': 'application/json',
      cookie: `idp_portal=${opts.session ?? 'sessOwner'}; ${ADMIN_API_CSRF_COOKIE}=${CSRF}`,
      ...(opts.ticket ? { 'x-owner-authorisation': opts.ticket } : {}),
    },
    body: method === 'GET' ? undefined : JSON.stringify({ ...(opts.body ?? {}), ...(opts.csrf === false ? {} : { csrf: CSRF }) }),
  });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
}

// Only the audit-chain incidents: the deliberate refusals earlier in the sequence (a non-owner, a ticket for another break) are, correctly, recorded as owner_op_denied.
const incidents = async () => (await pool.query<{ kind: string; sequence_number: string }>("SELECT kind, sequence_number::text FROM security_incidents WHERE kind = 'audit_chain_broken' ORDER BY sequence_number")).rows;
const lockIsOn = () => { resetIncidentLockCache(); return activeIncidentLock(lockFile) !== null; };
async function waitFor(cond: () => boolean | Promise<boolean>, ms = 8000): Promise<void> {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (await cond()) return; await settle(50); }
  throw new Error('timed out waiting for the condition');
}

beforeAll(async () => {
  __setKdfParamsForTests({ logN: 10, r: 8, p: 1 });
  const admin = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await admin.connect();
  try { await admin.query(`CREATE DATABASE "${scratchName}"`); } finally { await admin.end(); }
  mockScratch.pool = new pg.Pool({ connectionString: scratchUrl, max: 8 });
  const files = fs.readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql') && !f.endsWith('.down.sql')).sort();
  for (const f of files) await pool.query(fs.readFileSync(path.join(MIGRATIONS, f), 'utf8'));

  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'incident-ack-'));
  lockFile = path.join(dir, 'incident.lock');
  keyFile = tempKeyFilePath();
  createKeyFile(keyFile);
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
  enrolled = { answers, totpSecret };

  // The real incident handler in `contain` mode, writing a real lock file; every other step is the production default.
  resetIncidentState();
  const handler = createIncidentHandler({
    ...defaultDeps,
    mode: () => 'contain',
    lock: async (reason, kind) => (writeIncidentLock(lockFile, { reason, kind }) ? 'file' : 'exists'),
  });
  unsubscribe = onSecurityEvent(handler);

  const app = express();
  app.use(incidentReadOnlyGuard({ lock: () => activeIncidentLock(lockFile) }));
  app.use('/api/v1/admin', adminMutationsRouter({} as never));
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 90_000);

afterAll(async () => {
  unsubscribe();
  resetIncidentState();
  await new Promise<void>((r) => server.close(() => r()));
  await settle();
  await mockScratch.pool?.end();
  mockScratch.pool = null;
  const admin = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await admin.connect();
  try { await admin.query(`DROP DATABASE IF EXISTS "${scratchName}" WITH (FORCE)`); } finally { await admin.end(); }
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(path.dirname(keyFile), { recursive: true, force: true });
}, 30_000);

describe('a broken audit log locks the platform, and the owner can still acknowledge it from the console', () => {
  let firstBreak = '';
  let secondBreak = '';

  it('two edited audit entries are found and lock the platform read-only', async () => {
    for (let i = 1; i <= 6; i += 1) await writeAudit(REQ, 'seed@test.invalid', 'test.seed', `row ${i}`, { i });
    const { rows } = await pool.query<{ sequence_number: string }>('SELECT sequence_number::text FROM idp_admin_audit ORDER BY sequence_number');
    firstBreak = rows[1]!.sequence_number;
    secondBreak = rows[3]!.sequence_number;
    for (const seq of [firstBreak, secondBreak]) await pool.query("UPDATE idp_admin_audit SET target = 'edited later' WHERE sequence_number = $1", [seq]);

    resetAuditChainState();
    const chain = await runAuditChainCheck(); // what the scheduled job does
    expect(chain.valid).toBe(false);
    expect(chain.openBreaks).toBe(2);

    await waitFor(() => lockIsOn());
    expect((await incidents()).map((i) => i.kind)).toEqual(['audit_chain_broken']);
    // locked: an ordinary change is refused by the lock, reads still work
    const refused = await call('POST', '/api/v1/admin/users', { body: {} });
    expect(refused.status).toBe(403);
    expect(refused.json.error.code).toBe('INCIDENT_READ_ONLY');
  }, 30_000);

  it('the acknowledgement route is reached while locked, and its own protections still apply', async () => {
    const body = { sequenceNumber: firstBreak, kind: 'hash', reason: REASON };
    // no owner authorisation: the owner gate answers, not the lock
    const none = await call('POST', ACK, { body });
    expect(none.status).toBe(403);
    expect(none.json.error.code).toBe('OWNER_AUTHORISATION_REQUIRED');
    // an ordinary administrator: the route's own refusal
    state.platform = false;
    const nonOwner = await call('POST', ACK, { body, session: 'sessAdmin' });
    expect(nonOwner.status).toBe(403);
    expect(nonOwner.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    state.platform = true;
    // the right owner, a valid authorisation, but no CSRF token: refused, and the ticket is not spent on a 4xx
    const ticket = await ticketFor('audit.chain.acknowledge', firstBreak);
    const noCsrf = await call('POST', ACK, { body, ticket, csrf: false });
    expect(noCsrf.status).toBe(403);
    expect(noCsrf.json.error.code).toBe('ERR-INVALID-CSRF');
    await settle();
    // a ticket for another break is refused
    const other = await call('POST', ACK, { body: { ...body, sequenceNumber: secondBreak }, ticket });
    expect(other.json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM idp_audit_chain_acknowledgements')).rows[0].n).toBe(0);
    expect(lockIsOn()).toBe(true);
  }, 30_000);

  it('acknowledging the first break leaves one open and records NO new incident (the mirror\'s incident #3); the lock stays', async () => {
    const ticket = await ticketFor('audit.chain.acknowledge', firstBreak);
    const r = await call('POST', ACK, { body: { sequenceNumber: firstBreak, kind: 'hash', reason: REASON }, ticket });
    expect(r.status).toBe(200);
    expect(r.json.data.chain).toMatchObject({ valid: false, openBreaks: 1, acknowledgedBreaks: 1 });
    expect(JSON.stringify(r.json)).not.toMatch(/"pin"/);
    await settle(600);
    expect((await incidents()).map((i) => i.kind)).toEqual(['audit_chain_broken']); // still the one
    expect(lockIsOn()).toBe(true);
    expect((await call('POST', '/api/v1/admin/users', { body: {} })).json.error.code).toBe('INCIDENT_READ_ONLY');
  }, 30_000);

  it('acknowledging the second break makes the chain verify as acknowledged, and nothing new is raised', async () => {
    const ticket = await ticketFor('audit.chain.acknowledge', secondBreak);
    const r = await call('POST', ACK, { body: { sequenceNumber: secondBreak, kind: 'hash', reason: REASON }, ticket });
    expect(r.status).toBe(200);
    expect(r.json.data.chain).toMatchObject({ valid: true, openBreaks: 0, acknowledgedBreaks: 2 });
    await settle(600); // the owner-authorisation audit entries are written after the response
    // the acknowledgement entries and the 'owner.operation.authorised' entries are part of the chain now, and the chain still verifies
    const { rows: acks } = await pool.query("SELECT COUNT(*)::int AS n FROM idp_admin_audit WHERE action = 'audit.chain_break_acknowledged'");
    expect(acks[0].n).toBe(2);
    const fresh = await verifyAuditChain();
    expect(fresh).toMatchObject({ valid: true, openBreaks: 0, acknowledgedBreaks: 2 });
    // a later scheduled pass, and one after a restart (state forgotten), see an acknowledged chain: no new event
    await runAuditChainCheck();
    resetAuditChainState();
    await runAuditChainCheck();
    await settle(600);
    expect((await incidents()).map((i) => i.kind)).toEqual(['audit_chain_broken']);
  }, 30_000);

  it('the lock is still in force; only clearing it (the terminal command, here removing the file) lifts it', async () => {
    expect(lockIsOn()).toBe(true);
    expect((await call('POST', '/api/v1/admin/users', { body: {} })).json.error.code).toBe('INCIDENT_READ_ONLY');
    // an already-acknowledged break cannot be acknowledged twice
    const ticket = await ticketFor('audit.chain.acknowledge', firstBreak);
    const again = await call('POST', ACK, { body: { sequenceNumber: firstBreak, kind: 'hash', reason: REASON }, ticket });
    expect(again.status).toBe(409); // still listed, already acknowledged
    fs.rmSync(lockFile);
    expect(lockIsOn()).toBe(false);
    const after = await call('POST', '/api/v1/admin/users', { body: {} });
    expect(after.json?.error?.code).not.toBe('INCIDENT_READ_ONLY');
  }, 30_000);
});
