/**
 * Owner verification (Phase 4), end to end on a SCRATCH database (idp_p4_scratch on the local Postgres; created, migrated and dropped here).
 *
 * Real: the owner router, the challenge service, the sealed store (a throwaway key file), the limiter, tickets signed with a real signing key, the
 * middleware, migrations 001-027. Mocked: the portal session lookup (two fake sessions), the platform-administrator check, the admin audit chain writer,
 * and the mail transport (a fake that records messages). Every secret in this file is generated at run time.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import { SignJWT, importJWK, type JWK } from 'jose';

const state = { platformIds: ['owner-account'] as string[], sendFails: false };
const SESSIONS: Record<string, { accountId: string; name: string; email: string; groups: string[]; createdAt: number }> = {};

jest.mock('../src/db/pool.js', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pg = require('pg');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { IDP_CONFIG } = require('../src/config.js');
  const u = new URL(IDP_CONFIG.databaseUrl);
  u.pathname = '/idp_p4_scratch';
  const pool = new pg.Pool({ connectionString: u.toString(), max: 8 });
  return { pool, query: (...a: unknown[]) => pool.query(...a) };
});
jest.mock('../src/portal/session.js', () => ({ getPortalSession: async (key: string) => SESSIONS[key] }));
jest.mock('../src/auth/platform-admin.js', () => ({ isPlatformAdminSession: async (s?: { accountId?: string }) => state.platformIds.includes(String(s?.accountId)) }));
const mockChainAudit = jest.fn(async (..._a: unknown[]) => undefined);
jest.mock('../src/admin/audit.js', () => ({ writeAudit: (...a: unknown[]) => mockChainAudit(...a) }));

import express from 'express';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { loadSigningJwks } from '../src/jwks.js';
import { ownerVerificationRouter } from '../src/api/v1/owner.router.js';
import { answerQuestions, finishChallenge, sendEmailCode, startChallenge, verifyEmailCode, verifyRecoveryCode, verifyTotpStep, OwnerError } from '../src/owner/challenge.js';
import { enrolOwner } from '../src/owner/enrol.js';
import { __setOwnerMailerForTests } from '../src/owner/mailer.js';
import { authoriseOwnerOperation, requireOwnerAuthorisation } from '../src/owner/middleware.js';
import { __setOwnerRuntimeForTests } from '../src/owner/runtime.js';
import { __setKdfParamsForTests, normaliseAnswer, hashAnswer, verifyAnswer } from '../src/owner/questions.js';
import { OWNER_OPERATIONS, findOperation, targetHash } from '../src/owner/registry.js';
import { createKeyFile, loadStoreKeys, open as openSealed, resetStoreKeyCache, seal } from '../src/owner/seal.js';
import { readStore } from '../src/owner/store.js';
import { OWNER_TICKET_TYP } from '../src/owner/ticket.js';
import { onSecurityEvent, type SecurityEvent } from '../src/ops/securityEvents.js';
import { createScratchDb, dropScratchDb, tempKeyFilePath, throwaway, totpCode } from './helpers/ownerHelpers.js';

const SCRATCH = 'idp_p4_scratch';
const OWNER = 'owner-account';
const SMTP_A = { host: 'smtp.test.invalid', port: 587, secure: false, user: 'mailer', pass: 'unused', from: 'noreply@test.invalid' };

let server: http.Server;
let base = '';
let keyFile = '';
let keys: ReturnType<typeof loadStoreKeys>;
let enrolled: { answers: string[]; email: string; totpSecret: string; codes: string[] };
const sent: Array<{ to: string; subject: string; text: string }> = [];
const events: SecurityEvent[] = [];
let unsubscribe: () => void;

const settle = (ms = 200) => new Promise((r) => setTimeout(r, ms));

const ctxOf = (key: string) => ({
  accountId: SESSIONS[key]!.accountId,
  sessionHash: sessionHashFor(key),
  // what the router passes: it writes to the admin audit chain (mocked here)
  chainAudit: async (action: string, detail: Record<string, unknown>) => void (await mockChainAudit({}, 'platform', action, 'platform', detail)),
});
// eslint-disable-next-line @typescript-eslint/no-require-imports
const sessionHashFor = (key: string): string => require('../src/owner/session.js').sessionHashOf(key);

/** The six digits of the last email the fake transport recorded (the test reads the code the same way the owner would). */
const lastEmailCode = (): string => {
  const m = /code is: (\d+)/.exec(sent[sent.length - 1]?.text ?? '');
  if (!m) throw new Error('no code was emailed');
  return m[1] as string;
};

async function enrol(): Promise<void> {
  const answers = [throwaway('movie'), throwaway('series'), throwaway('legion')];
  const email = `${throwaway('owner')}@mail.test.invalid`;
  // A fresh authenticator secret each time (20 random bytes as base32).
  const totpSecret = (await import('../src/auth/totp.js')).generateTotpSecret();
  const { codes } = await enrolOwner({
    keys,
    accountId: OWNER,
    questions: [
      { prompt: 'First question', answer: answers[0] as string },
      { prompt: 'Second question', answer: answers[1] as string },
      { prompt: 'Third question', answer: answers[2] as string },
    ],
    emailAddress: email,
    totpSecret,
  });
  enrolled = { answers, email, totpSecret, codes };
}

async function resetState(): Promise<void> {
  await pool.query('DELETE FROM owner_verification_challenges');
  await pool.query('DELETE FROM owner_verification_tickets');
  await pool.query('DELETE FROM owner_verification_audit');
  await pool.query('DELETE FROM owner_verification_store');
  await pool.query('DELETE FROM owner_verification_state');
  sent.length = 0;
  events.length = 0;
  mockChainAudit.mockClear();
  state.platformIds = [OWNER];
  state.sendFails = false;
  __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: SMTP_A });
  await enrol();
}

/** Run the whole sequence through the service functions and return the ticket. */
async function ticketFor(key: string, operation: string, target?: string, via: 'email' | 'recovery' = 'email'): Promise<string> {
  const ctx = ctxOf(key);
  const c = await startChallenge(ctx, { operation, target });
  await answerQuestions(ctx, c.challengeId, enrolled.answers);
  if (via === 'email') {
    await sendEmailCode(ctx, c.challengeId);
    await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
  } else {
    await verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[0] as string);
  }
  await pool.query('UPDATE owner_verification_state SET totp_last_step = 0');
  await verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret));
  return (await finishChallenge(ctx, c.challengeId)).ticket;
}

async function call(method: string, path: string, opts: { session?: string; ticket?: string; body?: unknown; cookie?: string } = {}) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  const cookies = [`idp_portal=${opts.session ?? 'sessA'}`];
  if (opts.cookie) cookies.push(opts.cookie);
  headers.cookie = cookies.join('; ');
  if (opts.ticket) headers['x-owner-authorisation'] = opts.ticket;
  const res = await fetch(`${base}${path}`, { method, headers, body: method === 'GET' ? undefined : JSON.stringify(opts.body ?? {}) });
  return { status: res.status, json: (await res.json().catch(() => ({}))) as any, setCookie: res.headers.get('set-cookie') ?? '' };
}

async function expectOwnerError(p: Promise<unknown>, code: string, status?: number) {
  const err = await p.then(
    () => null,
    (e) => e,
  );
  expect(err).toBeInstanceOf(OwnerError);
  expect((err as OwnerError).code).toBe(code);
  if (status) expect((err as OwnerError).status).toBe(status);
  return err as OwnerError;
}

beforeAll(async () => {
  __setKdfParamsForTests({ logN: 10, r: 8, p: 1 });
  await createScratchDb(IDP_CONFIG.databaseUrl, SCRATCH);
  keyFile = tempKeyFilePath();
  keys = createKeyFile(keyFile);
  SESSIONS.sessA = { accountId: OWNER, name: 'Owner', email: 'owner@test.invalid', groups: [IDP_CONFIG.adminGroup], createdAt: 1 };
  SESSIONS.sessB = { accountId: OWNER, name: 'Owner', email: 'owner@test.invalid', groups: [IDP_CONFIG.adminGroup], createdAt: 2 };
  SESSIONS.sessAdmin = { accountId: 'someone-else', name: 'Admin', email: 'admin@test.invalid', groups: [IDP_CONFIG.adminGroup], createdAt: 3 };
  SESSIONS.sessUser = { accountId: 'a-user', name: 'User', email: 'user@test.invalid', groups: [], createdAt: 4 };
  __setOwnerMailerForTests({
    async send(mail) {
      if (state.sendFails) throw new Error('relay down');
      sent.push(mail);
    },
  });
  unsubscribe = onSecurityEvent((e) => events.push(e));

  const app = express();
  app.use('/api/v1/owner/verification', ownerVerificationRouter());
  app.put('/op/:system', requireOwnerAuthorisation('license.save', (r) => String(r.params.system)), express.json(), (req, res) => {
    if (req.body?.boom) return void res.status(500).json({ boom: true });
    if (req.body?.bad) return void res.status(400).json({ bad: true });
    // A route's own platform check, exactly as the real routes do it (this answer must be unchanged for a non-owner).
    res.json({ ok: true });
  });
  app.delete('/other/:kid', requireOwnerAuthorisation('signing_key.retire', (r) => String(r.params.kid)), (_req, res) => res.json({ ok: true }));
  app.post('/nokey', requireOwnerAuthorisation('signing_key.generate'), (_req, res) => res.json({ ok: true }));
  app.post('/inline', async (req, res) => {
    if (!(await authoriseOwnerOperation(req, res, 'idp_admin.change', 'user-1'))) return;
    res.json({ ok: true });
  });
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 60_000);

beforeEach(async () => {
  await resetState();
});

afterAll(async () => {
  unsubscribe?.();
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
  await dropScratchDb(IDP_CONFIG.databaseUrl, SCRATCH);
  try {
    fs.rmSync(keyFile.replace(/[\\/][^\\/]+$/, ''), { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

describe('the gate (OWNER_VERIFICATION_REQUIRED true)', () => {
  it('no ticket -> 403 OWNER_AUTHORISATION_REQUIRED with the operation, target, label and warning', async () => {
    const r = await call('PUT', '/op/gms');
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('OWNER_AUTHORISATION_REQUIRED');
    expect(r.json.error.operation).toBe('license.save');
    expect(r.json.error.target).toBe('gms');
    expect(r.json.error.label).toBeTruthy();
    expect(r.json.error.warning).toBeTruthy();
    await settle(50);
    expect(events.map((e) => e.kind)).toContain('owner_op_without_sequence');
  });

  it('a valid ticket lets the one operation through, once; a replay is refused', async () => {
    const ticket = await ticketFor('sessA', 'license.save', 'gms');
    const first = await call('PUT', '/op/gms', { ticket });
    expect(first.status).toBe(200);
    await settle();
    const replay = await call('PUT', '/op/gms', { ticket });
    expect(replay.status).toBe(403);
    expect(replay.json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    const { rows } = await pool.query("SELECT state FROM owner_verification_tickets");
    expect(rows.map((r) => r.state)).toEqual(['consumed']);
    expect(mockChainAudit.mock.calls.some((c) => c[2] === 'owner.operation.authorised')).toBe(true);
  });

  it('two simultaneous requests with one ticket: exactly one passes', async () => {
    const ticket = await ticketFor('sessA', 'license.save', 'gms');
    const results = await Promise.all([call('PUT', '/op/gms', { ticket }), call('PUT', '/op/gms', { ticket }), call('PUT', '/op/gms', { ticket })]);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 403)).toHaveLength(2);
  });

  it('a ticket for another operation, another target, or another session is refused', async () => {
    const forOther = await ticketFor('sessA', 'signing_key.retire', 'kid-1');
    expect((await call('PUT', '/op/gms', { ticket: forOther })).json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    const gms = await ticketFor('sessA', 'license.save', 'gms');
    const wrongTarget = await call('PUT', '/op/dms', { ticket: gms });
    expect(wrongTarget.status).toBe(403);
    expect(wrongTarget.json.error.message).toMatch(/something else/);
    const wrongSession = await call('PUT', '/op/gms', { ticket: gms, session: 'sessB' });
    expect(wrongSession.status).toBe(403);
    expect(wrongSession.json.error.message).toMatch(/different sign-in/);
    // none of those attempts spent it: the right session and target still works
    expect((await call('PUT', '/op/gms', { ticket: gms })).status).toBe(200);
    await settle(50);
    expect(events.some((e) => e.kind === 'owner_op_denied')).toBe(true);
  });

  it('an expired ticket is refused (token past its expiry, and a row past its expiry)', async () => {
    const [jwk] = await loadSigningJwks();
    const key = await importJWK(jwk as unknown as JWK, 'RS256');
    const past = Math.floor(Date.now() / 1000) - 600;
    const sid = sessionHashFor('sessA');
    const old = await new SignJWT({ op: 'license.save', sid, th: targetHash('license.save', 'gms') })
      .setProtectedHeader({ alg: 'RS256', typ: OWNER_TICKET_TYP, kid: String(jwk!.kid) })
      .setIssuer(IDP_CONFIG.issuer)
      .setAudience('sso')
      .setSubject(OWNER)
      .setJti(crypto.randomUUID())
      .setIssuedAt(past)
      .setExpirationTime(past + 300)
      .sign(key);
    const r = await call('PUT', '/op/gms', { ticket: old });
    expect(r.status).toBe(403);
    expect(r.json.error.message).toMatch(/expired/);

    const fresh = await ticketFor('sessA', 'license.save', 'gms');
    await pool.query("UPDATE owner_verification_tickets SET expires_at = NOW() - INTERVAL '1 minute'");
    const r2 = await call('PUT', '/op/gms', { ticket: fresh });
    expect(r2.status).toBe(403);
    expect(r2.json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
  });

  it('a forged, garbled or unsigned ticket is refused', async () => {
    for (const t of ['garbage', 'a.b.c', `${Buffer.from(JSON.stringify({ alg: 'none', typ: OWNER_TICKET_TYP })).toString('base64url')}.e30.`]) {
      const r = await call('PUT', '/op/gms', { ticket: t });
      expect(r.status).toBe(403);
      expect(r.json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
    }
  });

  it('a request refused with a 4xx puts the ticket back; one that fails on the server spends it', async () => {
    const ticket = await ticketFor('sessA', 'license.save', 'gms');
    expect((await call('PUT', '/op/gms', { ticket, body: { bad: true } })).status).toBe(400);
    await settle();
    expect((await pool.query('SELECT state FROM owner_verification_tickets')).rows[0].state).toBe('issued');
    expect((await call('PUT', '/op/gms', { ticket, body: { boom: true } })).status).toBe(500);
    await settle();
    expect((await pool.query('SELECT state FROM owner_verification_tickets')).rows[0].state).toBe('consumed');
    expect((await call('PUT', '/op/gms', { ticket })).status).toBe(403);
  });

  it('not enrolled -> OWNER_NOT_ENROLLED (refused, never allowed)', async () => {
    await pool.query('DELETE FROM owner_verification_store');
    const r = await call('PUT', '/op/gms');
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('OWNER_NOT_ENROLLED');
    const start = await call('POST', '/api/v1/owner/verification/start', { body: { operation: 'license.save', target: 'gms', csrf: 'x' } });
    // the CSRF check comes first for a POST; ask for a token and try again
    expect(start.status).toBe(403);
    const status = await call('GET', '/api/v1/owner/verification/status');
    expect(status.json.data.enrolled).toBe(false);
    const csrf = status.json.data.csrf as string;
    const start2 = await call('POST', '/api/v1/owner/verification/start', { body: { operation: 'license.save', target: 'gms', csrf }, cookie: `idp_owner_csrf=${csrf}` });
    expect(start2.status).toBe(403);
    expect(start2.json.error.code).toBe('OWNER_NOT_ENROLLED');
  });

  it('an unreadable store (missing or wrong key file, or a tampered document) is refused, not read as "not enrolled"', async () => {
    const good = keyFile;
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: `${good}.missing`, smtp: SMTP_A });
    let r = await call('PUT', '/op/gms');
    expect(r.json.error.code).toBe('OWNER_STORE_UNREADABLE');
    // a different, valid key file
    const other = tempKeyFilePath();
    createKeyFile(other);
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: other, smtp: SMTP_A });
    expect(((await readStore()) as { reason?: string }).reason).toBe('wrong_key');
    r = await call('PUT', '/op/gms');
    expect(r.json.error.code).toBe('OWNER_STORE_UNREADABLE');
    // back to the right key; tamper with the sealed bytes
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: good, smtp: SMTP_A });
    resetStoreKeyCache();
    await pool.query("UPDATE owner_verification_store SET sealed = regexp_replace(sealed, '.$', 'A') || 'x'");
    expect(((await readStore()) as { reason?: string }).reason).toBe('corrupt');
    expect((await call('PUT', '/op/gms')).json.error.code).toBe('OWNER_STORE_UNREADABLE');
  });

  it('a session that is not the platform administrator is left to the route, and the inline form answers the same 403 as today', async () => {
    state.platformIds = [];
    // as middleware: it does not decide; the route's own check answers (here the route is open, which proves the middleware let it through untouched)
    expect((await call('PUT', '/op/gms', { session: 'sessAdmin' })).status).toBe(200);
    const inline = await call('POST', '/inline', { session: 'sessAdmin' });
    expect(inline.status).toBe(403);
    expect(inline.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    await settle(50);
    expect(events.some((e) => e.kind === 'owner_op_denied' && e.detail?.reason === 'not_platform_admin')).toBe(true);
  });

  it('with the setting false nothing is checked', async () => {
    __setOwnerRuntimeForTests({ required: false, storeKeyFile: keyFile, smtp: SMTP_A });
    expect((await call('PUT', '/op/gms')).status).toBe(200);
    expect((await call('POST', '/inline')).status).toBe(200);
  });

  it('a route naming an operation that is not in the registry is refused', async () => {
    const app = express();
    app.get('/x', requireOwnerAuthorisation('no.such.operation'), (_q, res) => res.json({ ok: true }));
    const s = http.createServer(app);
    await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
    const res = await fetch(`http://127.0.0.1:${(s.address() as AddressInfo).port}/x`, { headers: { cookie: 'idp_portal=sessA' } });
    expect(res.status).toBe(500);
    await new Promise<void>((r) => s.close(() => r()));
  });
});

describe('the sequence', () => {
  it('runs in order: no skipping a step', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(verifyEmailCode(ctx, c.challengeId, '12345678'), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret)), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await expectOwnerError(verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret)), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
  });

  it('a challenge belongs to the session that started it', async () => {
    const c = await startChallenge(ctxOf('sessA'), { operation: 'license.save', target: 'gms' });
    await expectOwnerError(answerQuestions(ctxOf('sessB'), c.challengeId, enrolled.answers), 'OWNER_CHALLENGE_EXPIRED', 410);
  });

  it('answers are normalised (case, spaces, accents); a wrong one fails and counts', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    const wrong = await expectOwnerError(answerQuestions(ctx, c.challengeId, [enrolled.answers[0]!, 'nope-nope', enrolled.answers[2]!]), 'OWNER_VERIFICATION_FAILED', 403);
    expect(wrong.extra.attemptsLeft).toBe(4);
    const messy = enrolled.answers.map((a) => `  ${a.toUpperCase().replace('-', '  -  ')}  `);
    await answerQuestions(ctx, c.challengeId, messy.map((m) => m.replace(/\s+-\s+/g, '-')));
  });

  it('five wrong answers lock the sequence; nothing is checked while locked; it lifts after the lock', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    for (let i = 0; i < 4; i += 1) await expectOwnerError(answerQuestions(ctx, c.challengeId, ['a1', 'b2', 'c3']), 'OWNER_VERIFICATION_FAILED', 403);
    const locked = await expectOwnerError(answerQuestions(ctx, c.challengeId, ['a1', 'b2', 'c3']), 'OWNER_VERIFICATION_LOCKED', 423);
    expect(Number(locked.extra.retryAfterSeconds)).toBeGreaterThan(0);
    // even the right answers are refused during the lock
    await expectOwnerError(answerQuestions(ctx, c.challengeId, enrolled.answers), 'OWNER_VERIFICATION_LOCKED', 423);
    await expectOwnerError(startChallenge(ctx, { operation: 'license.save', target: 'gms' }), 'OWNER_VERIFICATION_LOCKED', 423);
    await settle(50);
    expect(events.map((e) => e.kind)).toEqual(expect.arrayContaining(['owner_verification_failed', 'owner_verification_locked']));
    expect(mockChainAudit.mock.calls.some((c2) => c2[2] === 'owner.verification.locked')).toBe(true);
    // the lock is in the database and escalates
    const row = (await pool.query('SELECT lockout_level, locked_until FROM owner_verification_state')).rows[0];
    expect(row.lockout_level).toBe(1);
    // time passes
    await pool.query("UPDATE owner_verification_state SET locked_until = NOW() - INTERVAL '1 second'");
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
  });

  it('the second lock lasts longer than the first (escalation) and a completed run resets it', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    const lockOnce = async () => {
      for (let i = 0; i < 4; i += 1) await expectOwnerError(answerQuestions(ctx, c.challengeId, ['a1', 'b2', 'c3']), 'OWNER_VERIFICATION_FAILED');
      return expectOwnerError(answerQuestions(ctx, c.challengeId, ['a1', 'b2', 'c3']), 'OWNER_VERIFICATION_LOCKED');
    };
    const first = await lockOnce();
    await pool.query("UPDATE owner_verification_state SET locked_until = NOW() - INTERVAL '1 second'");
    const second = await lockOnce();
    expect(Number(second.extra.retryAfterSeconds)).toBeGreaterThan(Number(first.extra.retryAfterSeconds));
    await pool.query("UPDATE owner_verification_state SET locked_until = NOW() - INTERVAL '1 second'");
    await ticketFor('sessA', 'license.save', 'gms');
    expect((await pool.query('SELECT lockout_level, consecutive_failures FROM owner_verification_state')).rows[0]).toEqual({ lockout_level: 0, consecutive_failures: 0 });
  });

  it('the emailed code is single use, short-lived and limited; a wrong one counts', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    const sentOk = await sendEmailCode(ctx, c.challengeId);
    expect(sentOk.maskedAddress).toMatch(/\*\*\*/);
    expect(sentOk.maskedAddress).not.toContain(enrolled.email);
    // a second send is held back for the resend pause
    await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_RATE_LIMITED', 429);
    const code = lastEmailCode();
    const wrong = code === '00000000' ? '11111111' : '00000000';
    await expectOwnerError(verifyEmailCode(ctx, c.challengeId, wrong), 'OWNER_VERIFICATION_FAILED', 403);
    await verifyEmailCode(ctx, c.challengeId, code);
    // the code is gone: asking to verify again (a different step state) does not re-open it
    const stored = (await pool.query('SELECT email_code_hash FROM owner_verification_challenges WHERE id = $1', [c.challengeId])).rows[0];
    expect(stored.email_code_hash).toBeNull();
    // expired code
    const c2 = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c2.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c2.challengeId);
    await pool.query("UPDATE owner_verification_challenges SET email_code_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1", [c2.challengeId]);
    await expectOwnerError(verifyEmailCode(ctx, c2.challengeId, lastEmailCode()), 'OWNER_EMAIL_CODE_EXPIRED', 410);
  });

  it('the authenticator code cannot be replayed', async () => {
    const t1 = await ticketFor('sessA', 'license.save', 'gms');
    expect(t1).toBeTruthy();
    // second run immediately, WITHOUT resetting the replay guard, using the same time step
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c.challengeId);
    await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
    await expectOwnerError(verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret)), 'OWNER_VERIFICATION_FAILED', 403);
  });

  it('a recovery code is refused while the emailed code is available', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await expectOwnerError(verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[0]!), 'OWNER_RECOVERY_NOT_ALLOWED', 409);
  });

  it('email unavailable (SMTP removed): an unused recovery code replaces it, once, and the other two factors are still required', async () => {
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: { ...SMTP_A, host: '' } });
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.emailAvailable).toBe(false);
    expect(c.emailUnavailableReason).toBe('smtp_not_configured');
    await expectOwnerError(answerQuestions(ctx, c.challengeId, ['x1', 'x2', 'x3']), 'OWNER_VERIFICATION_FAILED');
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    const unavailable = await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_EMAIL_UNAVAILABLE', 409);
    expect(unavailable.extra.recoveryCodeAvailable).toBe(true);
    await verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[0]!);
    // the authenticator is still required
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await pool.query('UPDATE owner_verification_state SET totp_last_step = 0');
    await verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret));
    const t = await finishChallenge(ctx, c.challengeId);
    expect(t.ticket).toBeTruthy();
    // and it works at the gate
    expect((await call('PUT', '/op/gms', { ticket: t.ticket })).status).toBe(200);
    // the same code cannot be used again
    const c2 = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c2.challengeId, enrolled.answers);
    const again = await expectOwnerError(verifyRecoveryCode(ctx, c2.challengeId, enrolled.codes[0]!), 'OWNER_VERIFICATION_FAILED', 403);
    expect(again.message).toMatch(/already used/);
    await verifyRecoveryCode(ctx, c2.challengeId, enrolled.codes[1]!);
  });

  it('email unavailable and NO recovery code left: the sequence cannot be completed', async () => {
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: { ...SMTP_A, host: '' } });
    const store = await readStore();
    if (store.state !== 'ok') throw new Error('store');
    for (const r of store.doc.recoveryCodes) await pool.query('INSERT INTO owner_recovery_codes_used (code_id) VALUES ($1)', [r.id]);
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.recoveryCodeAvailable).toBe(false);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    const unavailable = await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_EMAIL_UNAVAILABLE', 409);
    expect(unavailable.extra.recoveryCodeAvailable).toBe(false);
    await expectOwnerError(verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[2]!), 'OWNER_VERIFICATION_FAILED', 403);
    await expectOwnerError(verifyRecoveryCode(ctx, c.challengeId, 'AAAAA-AAAAA-AAAAA-AAAAA'), 'OWNER_VERIFICATION_FAILED', 403);
    await expectOwnerError(verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret)), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
  });

  it('SMTP changed since enrolment (owner decision 2026-10-21): the emailed code stays available and is sent through whatever relay is configured now', async () => {
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: { ...SMTP_A, host: 'smtp.elsewhere.invalid' } });
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.emailAvailable).toBe(true);
    expect(c.emailUnavailableReason).toBeNull();
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    const sent = await sendEmailCode(ctx, c.challengeId);
    expect(sent.sent).toBe(true);
  });

  it('SMTP removed altogether: the emailed code is unavailable (reason smtp_not_configured) and a recovery code takes its place', async () => {
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: { host: '', port: 587, secure: false, user: '', pass: '', from: '' } });
    const c = await startChallenge(ctxOf('sessA'), { operation: 'license.save', target: 'gms' });
    expect(c.emailAvailable).toBe(false);
    expect(c.emailUnavailableReason).toBe('smtp_not_configured');
  });

  it('the relay failing mid-run (unreachable) makes the email factor unavailable for that run and allows a recovery code', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    state.sendFails = true;
    const err = await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_EMAIL_UNAVAILABLE', 409);
    expect(err.extra.recoveryCodeAvailable).toBe(true);
    await verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[3]!);
  });

  it('unknown and terminal-only operations cannot be started over HTTP', async () => {
    const ctx = ctxOf('sessA');
    await expectOwnerError(startChallenge(ctx, { operation: 'no.such.op' }), 'ERR-NOT-FOUND', 404);
    await expectOwnerError(startChallenge(ctx, { operation: 'owner.store.change' }), 'ERR-NOT-FOUND', 404);
    await expectOwnerError(startChallenge(ctx, { operation: 'license.save' }), 'ERR-VALIDATION-FAILED', 400);
  });
});

describe('the HTTP API', () => {
  const csrfCookie = (csrf: string) => `idp_owner_csrf=${csrf}`;

  it('only the platform administrator reaches it; anyone else gets 404, and a missing CSRF token is refused', async () => {
    const asOwner = await call('GET', '/api/v1/owner/verification/status');
    expect(asOwner.status).toBe(200);
    expect(asOwner.json.data.required).toBe(true);
    expect(asOwner.json.data.enrolled).toBe(true);
    const asAdmin = await call('GET', '/api/v1/owner/verification/status', { session: 'sessAdmin' });
    // the administrator who is not the owner: 404, exactly like a path that does not exist
    state.platformIds = [OWNER];
    expect(asAdmin.status).toBe(404);
    expect(asAdmin.json.error.code).toBe('ERR-NOT-FOUND');
    const finish = await call('POST', '/api/v1/owner/verification/finish', { body: { challengeId: 'x' } });
    expect(finish.status).toBe(403);
    expect(finish.json.error.code).toBe('ERR-INVALID-CSRF');
    const notAdmin = await call('GET', '/api/v1/owner/verification/status', { session: 'sessUser' });
    expect([401, 403, 404]).toContain(notAdmin.status);
    const anon = await fetch(`${base}/api/v1/owner/verification/status`);
    expect([401, 403, 404]).toContain(anon.status);
  });

  it('status lists every HTTP operation with its warning and reveals no secret', async () => {
    const r = await call('GET', '/api/v1/owner/verification/status');
    const text = JSON.stringify(r.json);
    for (const secret of [...enrolled.answers, enrolled.email, enrolled.totpSecret, ...enrolled.codes]) expect(text).not.toContain(secret);
    const keysListed = (r.json.data.operations as Array<{ key: string; warning: string }>).map((o) => o.key);
    expect(keysListed).toEqual(OWNER_OPERATIONS.filter((o) => !o.cli).map((o) => o.key));
    for (const o of r.json.data.operations) expect(o.warning.length).toBeGreaterThan(20);
  });

  it('the whole sequence over HTTP returns a ticket the gate accepts once', async () => {
    const status = await call('GET', '/api/v1/owner/verification/status');
    const csrf = status.json.data.csrf as string;
    const post = (path: string, body: Record<string, unknown>) => call('POST', `/api/v1/owner/verification/${path}`, { body: { ...body, csrf }, cookie: csrfCookie(csrf) });
    const start = await post('start', { operation: 'license.save', target: 'gms' });
    expect(start.status).toBe(200);
    const id = start.json.data.challengeId as string;
    expect(start.json.data.questions).toHaveLength(3);
    expect((await post('answer-questions', { challengeId: id, answers: enrolled.answers })).status).toBe(200);
    expect((await post('send-email-code', { challengeId: id })).json.data.sent).toBe(true);
    expect((await post('verify-email-code', { challengeId: id, code: lastEmailCode() })).status).toBe(200);
    await pool.query('UPDATE owner_verification_state SET totp_last_step = 0');
    expect((await post('verify-totp', { challengeId: id, code: totpCode(enrolled.totpSecret) })).status).toBe(200);
    const fin = await post('finish', { challengeId: id });
    expect(fin.status).toBe(200);
    expect(fin.json.data.operation).toBe('license.save');
    expect(fin.json.data.audience).toBe('sso');
    expect((await call('PUT', '/op/gms', { ticket: fin.json.data.ticket })).status).toBe(200);
    // a second finish for the same run is refused
    const again = await post('finish', { challengeId: id });
    expect(again.status).toBe(410);
  });

  it('a wrong answer over HTTP is a plain 403 with attemptsLeft and no hint about which answer', async () => {
    const status = await call('GET', '/api/v1/owner/verification/status');
    const csrf = status.json.data.csrf as string;
    const post = (path: string, body: Record<string, unknown>) => call('POST', `/api/v1/owner/verification/${path}`, { body: { ...body, csrf }, cookie: csrfCookie(csrf) });
    const id = (await post('start', { operation: 'license.save', target: 'gms' })).json.data.challengeId as string;
    const r = await post('answer-questions', { challengeId: id, answers: ['a1', 'b2', 'c3'] });
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('OWNER_VERIFICATION_FAILED');
    expect(r.json.error.attemptsLeft).toBe(4);
  });
});

describe('the ticket for another system (DMS) follows the cross-system contract', () => {
  it('is an RS256 JWS DMS can verify with the published public key of SSO: typ, iss, aud dms, sub, op, jti, a lifetime of at most 330 s', async () => {
    const ticket = await ticketFor('sessA', 'dms.tenant.create');
    const [h, p, sig] = ticket.split('.') as [string, string, string];
    const header = JSON.parse(Buffer.from(h, 'base64url').toString());
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    expect(header).toMatchObject({ alg: 'RS256', typ: 'kcms-owner-ticket+jwt' });
    const jwk = (await loadSigningJwks()).find((k) => k.kid === header.kid)!;
    // the public half only, as /jwks publishes it (DMS turns it into a PEM exactly like this)
    const { d, p: _p, q, dp, dq, qi, ...publicJwk } = jwk as Record<string, unknown>;
    void d; void _p; void q; void dp; void dq; void qi;
    const pem = (await import('node:crypto')).createPublicKey({ key: publicJwk as never, format: 'jwk' }).export({ type: 'spki', format: 'pem' });
    expect((await import('node:crypto')).verify('RSA-SHA256', Buffer.from(`${h}.${p}`), pem, Buffer.from(sig, 'base64url'))).toBe(true);
    expect(claims.iss).toBe(IDP_CONFIG.issuer);
    expect(claims.aud).toBe('dms');
    expect(claims.sub).toBe(OWNER);
    expect(claims.op).toBe('dms.tenant.create');
    expect(claims.jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(300);
    // it is not accepted by SSO's own gate (audience dms), so it cannot be turned into an SSO operation
    expect((await call('PUT', '/op/gms', { ticket })).json.error.code).toBe('OWNER_AUTHORISATION_INVALID');
  });
});

describe('nothing secret is recorded', () => {
  it('the audit rows, security events, chain entries, emails and the database hold no answer, address, secret, code or ticket', async () => {
    const ticket = await ticketFor('sessA', 'license.save', 'gms');
    await call('PUT', '/op/gms', { ticket });
    await call('PUT', '/op/dms', { ticket }); // a denial
    await expectOwnerError(answerQuestions(ctxOf('sessA'), (await startChallenge(ctxOf('sessA'), { operation: 'license.save', target: 'gms' })).challengeId, ['q', 'r', 's']), 'OWNER_VERIFICATION_FAILED');
    await settle();
    const everything = JSON.stringify({
      audit: (await pool.query('SELECT * FROM owner_verification_audit')).rows,
      events,
      chain: mockChainAudit.mock.calls.map((c) => [c[2], c[3], c[4]]),
      tickets: (await pool.query('SELECT * FROM owner_verification_tickets')).rows,
      challenges: (await pool.query('SELECT * FROM owner_verification_challenges')).rows,
      store: (await pool.query('SELECT * FROM owner_verification_store')).rows,
      state: (await pool.query('SELECT * FROM owner_verification_state')).rows,
    });
    const secrets = [...enrolled.answers, enrolled.email, enrolled.email.split('@')[0]!, enrolled.totpSecret, ...enrolled.codes, ticket];
    for (const s of secrets) expect(everything).not.toContain(s);
    // the code that was emailed is not in the database either
    const code = lastEmailCode();
    expect(everything).not.toContain(`"${code}"`);
    // the real address IS in the email transport (that is its job) and only there
    expect(sent.every((m) => m.to === enrolled.email)).toBe(true);
  });
});

describe('the pieces', () => {
  it('normaliseAnswer: trim, lower-case, collapse spaces, strip accents', () => {
    expect(normaliseAnswer('  The  Matrix ')).toBe('the matrix');
    expect(normaliseAnswer('Amélie')).toBe('amelie');
    expect(normaliseAnswer('ÉCOLE\tdes   Fans')).toBe('ecole des fans');
  });

  it('hashes are salted, verify in both directions and reject a malformed stored value', async () => {
    const a = await hashAnswer(keys, 'Same Answer');
    const b = await hashAnswer(keys, 'same   answer');
    expect(a).not.toBe(b); // different salts
    expect(await verifyAnswer(keys, 'SAME answer', a)).toBe(true);
    expect(await verifyAnswer(keys, 'other', a)).toBe(false);
    expect(await verifyAnswer(keys, 'same answer', 'garbage')).toBe(false);
    expect(a).not.toContain('same');
  });

  it('seal: round trip, a changed byte or context fails, a different key fails', () => {
    const s = seal(keys, { a: 1 }, 'ctx');
    expect(openSealed(keys, s, 'ctx')).toEqual({ a: 1 });
    expect(() => openSealed(keys, s, 'other')).toThrow();
    const parts = s.split('.');
    parts[3] = Buffer.from('tampered').toString('base64url');
    expect(() => openSealed(keys, parts.join('.'), 'ctx')).toThrow();
    const otherPath = tempKeyFilePath();
    const otherKeys = createKeyFile(otherPath);
    expect(() => openSealed(otherKeys, s, 'ctx')).toThrow();
    resetStoreKeyCache();
  });

  it('the key file is 64 hex characters and refuses to be overwritten', () => {
    expect(fs.readFileSync(keyFile, 'utf8').trim()).toMatch(/^[0-9a-f]{64}$/);
    expect(() => createKeyFile(keyFile)).toThrow();
  });

  it('the registry: unique keys, plain warnings, targets only where the operation has one', () => {
    const keysSeen = new Set<string>();
    for (const o of OWNER_OPERATIONS) {
      expect(keysSeen.has(o.key)).toBe(false);
      keysSeen.add(o.key);
      expect(o.label.length).toBeGreaterThan(5);
      expect(o.warning.length).toBeGreaterThan(30);
      expect(o.warning).not.toMatch(/\b(jwt|totp|jti|oidc|sql)\b/i);
      expect(findOperation(o.key)).toBe(o);
      expect(targetHash(o.key, 'x') === null).toBe(!o.needsTarget);
    }
    expect(targetHash('license.save', 'gms')).not.toBe(targetHash('license.save', 'dms'));
    expect(targetHash('license.save', 'gms')).not.toBe(targetHash('license.extend', 'gms'));
  });
});
