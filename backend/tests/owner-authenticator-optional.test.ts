/**
 * The authenticator is an optional owner factor (OWNER_AUTHENTICATOR_REQUIRED, owner decision 2026-10-21), on a SCRATCH database (idp_p4_scratch3; created,
 * migrated and dropped here). What must hold:
 *
 *   - an enrolment made without the authenticator stores no secret, records `factors.authenticator = false` inside the sealed store and is verified with
 *     exactly two factors (questions + emailed code, or one recovery code when email cannot be used); a TOTP code is never accepted for it;
 *   - a store written before the field existed still requires the authenticator, and so does anything unclear (fail closed);
 *   - the factors demanded are the STORED ones: flipping OWNER_AUTHENTICATOR_REQUIRED later never relaxes (or tightens) an existing enrolment;
 *   - a recovery re-enrolment replaces the factors and clears what the old enrolment held;
 *   - the status says which it is; nothing secret is recorded.
 *
 * Mocked: the portal session lookup, the platform-administrator check, the admin audit chain writer, the mail transport. Every secret is generated at run time.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import fs from 'node:fs';

const state = { sendFails: false };
const SESSIONS: Record<string, { accountId: string; name: string; email: string; groups: string[]; createdAt: number }> = {};

jest.mock('../src/db/pool.js', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pg = require('pg');
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { IDP_CONFIG } = require('../src/config.js');
  const u = new URL(IDP_CONFIG.databaseUrl);
  u.pathname = '/idp_p4_scratch3';
  const pool = new pg.Pool({ connectionString: u.toString(), max: 8 });
  return { pool, query: (...a: unknown[]) => pool.query(...a) };
});
jest.mock('../src/portal/session.js', () => ({ getPortalSession: async (key: string) => SESSIONS[key] }));
jest.mock('../src/auth/platform-admin.js', () => ({ isPlatformAdminSession: async (s?: { accountId?: string }) => s?.accountId === 'owner-account' }));
const mockChainAudit = jest.fn(async (..._a: unknown[]) => undefined);
jest.mock('../src/admin/audit.js', () => ({ writeAudit: (...a: unknown[]) => mockChainAudit(...a) }));

import express from 'express';
import { generateTotpSecret } from '../src/auth/totp.js';
import { ownerVerificationRouter } from '../src/api/v1/owner.router.js';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { OwnerError, answerQuestions, finishChallenge, ownerStatus, sendEmailCode, startChallenge, verifyEmailCode, verifyRecoveryCode, verifyTotpStep } from '../src/owner/challenge.js';
import { enrolOwner } from '../src/owner/enrol.js';
import { __setOwnerMailerForTests } from '../src/owner/mailer.js';
import { __setKdfParamsForTests } from '../src/owner/questions.js';
import { __setOwnerRuntimeForTests, authenticatorRequiredForNewEnrolment } from '../src/owner/runtime.js';
import { createKeyFile, open as openSealed } from '../src/owner/seal.js';
import { authenticatorRequired, readStore, writeStore, type OwnerStoreDoc } from '../src/owner/store.js';
import { createScratchDb, dropScratchDb, tempKeyFilePath, throwaway, totpCode } from './helpers/ownerHelpers.js';

const SCRATCH = 'idp_p4_scratch3';
const OWNER = 'owner-account';
const SMTP_A = { host: 'smtp.test.invalid', port: 587, secure: false, user: 'mailer', pass: 'unused', from: 'noreply@test.invalid' };

let server: http.Server;
let base = '';
let keyFile = '';
let keys: ReturnType<typeof createKeyFile>;
let enrolled: { answers: string[]; email: string; totpSecret: string | undefined; codes: string[] };
const sent: Array<{ to: string; subject: string; text: string }> = [];

// eslint-disable-next-line @typescript-eslint/no-require-imports
const sessionHashFor = (key: string): string => require('../src/owner/session.js').sessionHashOf(key);
const ctxOf = (key: string) => ({
  accountId: SESSIONS[key]!.accountId,
  sessionHash: sessionHashFor(key),
  chainAudit: async (action: string, detail: Record<string, unknown>) => void (await mockChainAudit({}, 'platform', action, 'platform', detail)),
});
const lastEmailCode = (): string => {
  const m = /code is: (\d+)/.exec(sent[sent.length - 1]?.text ?? '');
  if (!m) throw new Error('no code was emailed');
  return m[1] as string;
};

async function enrol(authenticator: boolean): Promise<void> {
  const answers = [throwaway('movie'), throwaway('series'), throwaway('legion')];
  const email = `${throwaway('owner')}@mail.test.invalid`;
  const totpSecret = authenticator ? generateTotpSecret() : undefined;
  const { codes } = await enrolOwner({
    keys,
    accountId: OWNER,
    questions: [
      { prompt: 'First question', answer: answers[0] as string },
      { prompt: 'Second question', answer: answers[1] as string },
      { prompt: 'Third question', answer: answers[2] as string },
    ],
    emailAddress: email,
    ...(authenticator ? { totpSecret } : { authenticator: false }),
  });
  enrolled = { answers, email, totpSecret, codes };
}

async function resetState(): Promise<void> {
  for (const t of ['owner_verification_challenges', 'owner_verification_tickets', 'owner_verification_audit', 'owner_verification_store', 'owner_verification_state']) {
    await pool.query(`DELETE FROM ${t}`);
  }
  sent.length = 0;
  mockChainAudit.mockClear();
  state.sendFails = false;
  __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: SMTP_A });
}

/** Rewrite the sealed document the way an older build wrote it (no `factors` field). */
async function rewriteDoc(edit: (doc: OwnerStoreDoc) => void): Promise<void> {
  const store = await readStore();
  if (store.state !== 'ok') throw new Error('store');
  const doc = JSON.parse(JSON.stringify(store.doc)) as OwnerStoreDoc;
  edit(doc);
  const used = (await pool.query('SELECT code_id, used_at FROM owner_recovery_codes_used')).rows;
  await writeStore(store.keys, doc);
  for (const r of used) await pool.query('INSERT INTO owner_recovery_codes_used (code_id, used_at) VALUES ($1, $2) ON CONFLICT DO NOTHING', [r.code_id, r.used_at]);
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

const failuresNow = async (): Promise<number> => Number((await pool.query('SELECT consecutive_failures FROM owner_verification_state')).rows[0]?.consecutive_failures ?? 0);

/** Questions, then the emailed code. Returns the challenge id (the authenticator is NOT done here). */
async function twoFactors(ctx: ReturnType<typeof ctxOf>, operation = 'license.save', target = 'gms'): Promise<string> {
  const c = await startChallenge(ctx, { operation, target });
  await answerQuestions(ctx, c.challengeId, enrolled.answers);
  await sendEmailCode(ctx, c.challengeId);
  await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
  return c.challengeId;
}

beforeAll(async () => {
  __setKdfParamsForTests({ logN: 10, r: 8, p: 1 });
  await createScratchDb(IDP_CONFIG.databaseUrl, SCRATCH);
  keyFile = tempKeyFilePath();
  keys = createKeyFile(keyFile);
  SESSIONS.sessA = { accountId: OWNER, name: 'Owner', email: 'owner@test.invalid', groups: [IDP_CONFIG.adminGroup], createdAt: 1 };
  __setOwnerMailerForTests({
    async send(mail) {
      if (state.sendFails) throw new Error('relay down');
      sent.push(mail);
    },
  });
  const app = express();
  app.use('/api/v1/owner/verification', ownerVerificationRouter());
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}, 60_000);

beforeEach(async () => {
  await resetState();
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((r) => server.close(() => r()));
  await pool.end();
  await dropScratchDb(IDP_CONFIG.databaseUrl, SCRATCH);
  try {
    fs.rmSync(keyFile.replace(/[\\/][^\\/]+$/, ''), { recursive: true, force: true });
  } catch {
    /* best effort */
  }
}, 60_000);

describe('enrolment without the authenticator', () => {
  it('records the factors inside the sealed store and stores no authenticator secret at all', async () => {
    await enrol(false);
    const store = await readStore();
    if (store.state !== 'ok') throw new Error('store');
    expect(store.doc.factors).toEqual({ authenticator: false });
    expect(store.doc.totp).toBeUndefined();
    expect('totp' in store.doc).toBe(false);
    expect(authenticatorRequired(store.doc)).toBe(false);
    // the sealed bytes in the database open to exactly that document
    const row = (await pool.query('SELECT sealed FROM owner_verification_store WHERE id = 1')).rows[0];
    const opened = openSealed<OwnerStoreDoc>(keys, row.sealed, 'examplecorp-owner-store:v1');
    expect(JSON.stringify(opened)).not.toMatch(/totp|secret/i);
  });

  it('the enrolment tool refuses a half-way request: a secret is required with the authenticator and forbidden without it', async () => {
    const q = [
      { prompt: 'One?', answer: throwaway('a') },
      { prompt: 'Two?', answer: throwaway('b') },
      { prompt: 'Three?', answer: throwaway('c') },
    ];
    await expect(enrolOwner({ keys, accountId: OWNER, questions: q, emailAddress: 'o@mail.test.invalid' })).rejects.toThrow(/authenticator secret is needed/);
    await expect(enrolOwner({ keys, accountId: OWNER, questions: q, emailAddress: 'o@mail.test.invalid', authenticator: true })).rejects.toThrow(/authenticator secret is needed/);
    await expect(enrolOwner({ keys, accountId: OWNER, questions: q, emailAddress: 'o@mail.test.invalid', authenticator: false, totpSecret: generateTotpSecret() })).rejects.toThrow(/must not carry/);
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM owner_verification_store')).rows[0].n).toBe(0);
  });

  it('the enrolment is recorded without a secret in the audit row', async () => {
    await enrol(false);
    const row = (await pool.query("SELECT detail FROM owner_verification_audit WHERE event = 'enrolled'")).rows[0];
    expect(row.detail).toMatchObject({ authenticator: 'not used' });
    expect(JSON.stringify(row.detail)).not.toContain(enrolled.email);
  });
});

describe('verification without the authenticator: questions, then the emailed code, nothing else', () => {
  beforeEach(async () => {
    await enrol(false);
  });

  it('the run has two steps and says so', async () => {
    const c = await startChallenge(ctxOf('sessA'), { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email']);
    expect(c.authenticatorRequired).toBe(false);
  });

  it('questions + emailed code issue the ticket; the authenticator is never asked for', async () => {
    const ctx = ctxOf('sessA');
    const id = await twoFactors(ctx);
    const t = await finishChallenge(ctx, id);
    expect(t.ticket).toBeTruthy();
    expect((await pool.query('SELECT totp_ok_at FROM owner_verification_challenges WHERE id = $1', [id])).rows[0].totp_ok_at).toBeNull();
    // which factors were used is recorded, in the owner audit and in the admin audit chain
    const audit = (await pool.query("SELECT detail FROM owner_verification_audit WHERE event = 'ticket_issued'")).rows[0];
    expect(audit.detail).toMatchObject({ via: 'email', authenticator: 'not used' });
    const chain = mockChainAudit.mock.calls.find((c) => c[2] === 'owner.verification.ticket_issued');
    expect(chain?.[4]).toMatchObject({ secondFactor: 'email', authenticator: 'not used' });
  });

  it('the step answers list only the factors that remain', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    const afterQuestions = await answerQuestions(ctx, c.challengeId, enrolled.answers);
    expect(afterQuestions.steps).toEqual([{ id: 'questions', done: true }, { id: 'email', done: false }]);
    await sendEmailCode(ctx, c.challengeId);
    const afterEmail = await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
    expect(afterEmail.steps).toEqual([{ id: 'questions', done: true }, { id: 'email', done: true }]);
  });

  it('still never fewer than two factors: questions alone, or the email code without the questions, cannot finish', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    // a recovery code is not allowed while the emailed code works: it cannot stand in for it
    await expectOwnerError(verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[0]!), 'OWNER_RECOVERY_NOT_ALLOWED', 409);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
  });

  it('a wrong answer or a wrong emailed code still counts toward the lockout', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await expectOwnerError(answerQuestions(ctx, c.challengeId, ['a1', 'b2', 'c3']), 'OWNER_VERIFICATION_FAILED', 403);
    expect(await failuresNow()).toBe(1);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c.challengeId);
    const code = lastEmailCode();
    await expectOwnerError(verifyEmailCode(ctx, c.challengeId, code === '00000000' ? '11111111' : '00000000'), 'OWNER_VERIFICATION_FAILED', 403);
    expect(await failuresNow()).toBe(2);
    for (let i = 0; i < 2; i += 1) await expectOwnerError(verifyEmailCode(ctx, c.challengeId, code === '00000000' ? '11111111' : '00000000'), 'OWNER_VERIFICATION_FAILED', 403);
    // the fifth wrong attempt in a row locks the sequence, exactly as with three factors
    await expectOwnerError(verifyEmailCode(ctx, c.challengeId, code === '00000000' ? '11111111' : '00000000'), 'OWNER_VERIFICATION_LOCKED', 423);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_VERIFICATION_LOCKED', 423);
  });

  it('a recovery code replaces the emailed code only when email is unavailable, once, and still never means fewer than two factors', async () => {
    __setOwnerRuntimeForTests({ required: true, storeKeyFile: keyFile, smtp: { ...SMTP_A, host: '' } });
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email']);
    expect(c.emailAvailable).toBe(false);
    // the recovery code alone, without the questions, is refused
    await expectOwnerError(verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[0]!), 'OWNER_STEP_ORDER', 409);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[0]!);
    const t = await finishChallenge(ctx, c.challengeId);
    expect(t.ticket).toBeTruthy();
    expect((await pool.query("SELECT detail FROM owner_verification_audit WHERE event = 'ticket_issued'")).rows[0].detail).toMatchObject({ via: 'recovery', authenticator: 'not used' });
    // spent
    const c2 = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c2.challengeId, enrolled.answers);
    await expectOwnerError(verifyRecoveryCode(ctx, c2.challengeId, enrolled.codes[0]!), 'OWNER_VERIFICATION_FAILED', 403);
  });

  it('a relay that fails mid-run allows a recovery code in its place, with the questions still required', async () => {
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    state.sendFails = true;
    await expectOwnerError(sendEmailCode(ctx, c.challengeId), 'OWNER_EMAIL_UNAVAILABLE', 409);
    await verifyRecoveryCode(ctx, c.challengeId, enrolled.codes[1]!);
    expect((await finishChallenge(ctx, c.challengeId)).ticket).toBeTruthy();
  });

  it('an authenticator code is never accepted: refused outright, not counted, nothing stored', async () => {
    const ctx = ctxOf('sessA');
    const id = await twoFactors(ctx);
    // any six digits, including a perfectly valid code for some secret
    for (const code of ['123456', totpCode(generateTotpSecret())]) {
      const err = await expectOwnerError(verifyTotpStep(ctx, id, code), 'OWNER_AUTHENTICATOR_NOT_USED', 409);
      expect(err.message).toMatch(/does not use an authenticator/);
    }
    expect(await failuresNow()).toBe(0);
    expect((await pool.query('SELECT totp_ok_at FROM owner_verification_challenges WHERE id = $1', [id])).rows[0].totp_ok_at).toBeNull();
    expect(Number((await pool.query('SELECT totp_last_step FROM owner_verification_state')).rows[0]?.totp_last_step ?? 0)).toBe(0);
    // and the run is unaffected
    expect((await finishChallenge(ctx, id)).ticket).toBeTruthy();
  });

  it('works over HTTP: two steps, verify-totp is answered 409, finish issues the ticket', async () => {
    const call = async (method: string, path: string, body?: Record<string, unknown>, csrf?: string) => {
      const headers: Record<string, string> = { 'content-type': 'application/json', cookie: `idp_portal=sessA${csrf ? `; idp_owner_csrf=${csrf}` : ''}` };
      const res = await fetch(`${base}/api/v1/owner/verification${path}`, { method, headers, body: method === 'GET' ? undefined : JSON.stringify({ ...body, csrf }) });
      return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
    };
    const status = await call('GET', '/status');
    expect(status.json.data.authenticator).toBe(false);
    const csrf = status.json.data.csrf as string;
    const start = await call('POST', '/start', { operation: 'license.save', target: 'gms' }, csrf);
    expect(start.json.data.steps.map((s: { id: string }) => s.id)).toEqual(['questions', 'email']);
    expect(start.json.data.authenticatorRequired).toBe(false);
    const id = start.json.data.challengeId as string;
    await call('POST', '/answer-questions', { challengeId: id, answers: enrolled.answers }, csrf);
    await call('POST', '/send-email-code', { challengeId: id }, csrf);
    const ok = await call('POST', '/verify-email-code', { challengeId: id, code: lastEmailCode() }, csrf);
    expect(ok.json.data.steps).toEqual([{ id: 'questions', done: true }, { id: 'email', done: true }]);
    const totp = await call('POST', '/verify-totp', { challengeId: id, code: '123456' }, csrf);
    expect(totp.status).toBe(409);
    expect(totp.json.error.code).toBe('OWNER_AUTHENTICATOR_NOT_USED');
    const fin = await call('POST', '/finish', { challengeId: id }, csrf);
    expect(fin.status).toBe(200);
    expect(fin.json.data.ticket).toBeTruthy();
  });

  it('nothing secret is recorded: no answer, address, recovery code, email code or ticket anywhere', async () => {
    const ctx = ctxOf('sessA');
    const id = await twoFactors(ctx);
    const t = await finishChallenge(ctx, id);
    const everything = JSON.stringify({
      audit: (await pool.query('SELECT * FROM owner_verification_audit')).rows,
      chain: mockChainAudit.mock.calls.map((c) => [c[2], c[3], c[4]]),
      challenges: (await pool.query('SELECT * FROM owner_verification_challenges')).rows,
      store: (await pool.query('SELECT * FROM owner_verification_store')).rows,
      state: (await pool.query('SELECT * FROM owner_verification_state')).rows,
    });
    for (const s of [...enrolled.answers, enrolled.email, ...enrolled.codes, t.ticket]) expect(everything).not.toContain(s);
    expect(everything).not.toContain(`"${lastEmailCode()}"`);
  });
});

describe('the status says which kind of enrolment this is', () => {
  it('without: authenticator false; with: true; nothing readable: null', async () => {
    expect((await ownerStatus(OWNER)).authenticator).toBeNull();
    await enrol(false);
    expect(await ownerStatus(OWNER)).toMatchObject({ enrolled: true, authenticator: false });
    await enrol(true);
    expect(await ownerStatus(OWNER)).toMatchObject({ enrolled: true, authenticator: true });
    // someone else's account sees nothing about it
    expect(await ownerStatus('someone-else')).toMatchObject({ enrolled: false, authenticator: null });
  });
});

describe('an enrolment made WITH the authenticator is unchanged', () => {
  beforeEach(async () => {
    await enrol(true);
  });

  it('records factors.authenticator true next to the secret, and the run has three steps', async () => {
    const store = await readStore();
    if (store.state !== 'ok') throw new Error('store');
    expect(store.doc.factors).toEqual({ authenticator: true });
    expect(store.doc.totp?.secret).toBe(enrolled.totpSecret);
    const c = await startChallenge(ctxOf('sessA'), { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email', 'totp']);
    expect(c.authenticatorRequired).toBe(true);
  });

  it('questions + emailed code are not enough; the authenticator completes it and is recorded as used', async () => {
    const ctx = ctxOf('sessA');
    const id = await twoFactors(ctx);
    await expectOwnerError(finishChallenge(ctx, id), 'OWNER_STEP_ORDER', 409);
    await verifyTotpStep(ctx, id, totpCode(enrolled.totpSecret!));
    expect((await finishChallenge(ctx, id)).ticket).toBeTruthy();
    expect((await pool.query("SELECT detail FROM owner_verification_audit WHERE event = 'ticket_issued'")).rows[0].detail).toMatchObject({ authenticator: 'used' });
  });

  it('OWNER_AUTHENTICATOR_REQUIRED=false does NOT relax it: still three steps, still refused without the code', async () => {
    __setOwnerRuntimeForTests({ required: true, authenticatorRequired: false, storeKeyFile: keyFile, smtp: SMTP_A });
    expect(authenticatorRequiredForNewEnrolment()).toBe(false);
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email', 'totp']);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c.challengeId);
    await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(verifyTotpStep(ctx, c.challengeId, '000000'), 'OWNER_VERIFICATION_FAILED', 403);
    await verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret!));
    expect((await finishChallenge(ctx, c.challengeId)).ticket).toBeTruthy();
  });

  it('and the other way round: env true does not make an enrolment made without it start asking for one', async () => {
    await enrol(false);
    __setOwnerRuntimeForTests({ required: true, authenticatorRequired: true, storeKeyFile: keyFile, smtp: SMTP_A });
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email']);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c.challengeId);
    await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
    expect((await finishChallenge(ctx, c.challengeId)).ticket).toBeTruthy();
  });
});

describe('a store written before this change, and anything unclear, still requires the authenticator (fail closed)', () => {
  beforeEach(async () => {
    await enrol(true);
  });

  it('no `factors` field means authenticator = true', async () => {
    await rewriteDoc((doc) => {
      delete doc.factors;
    });
    const store = await readStore();
    if (store.state !== 'ok') throw new Error('store');
    expect(store.doc.factors).toBeUndefined();
    expect(authenticatorRequired(store.doc)).toBe(true);
    // even with the new setting off, an old store keeps all three factors
    __setOwnerRuntimeForTests({ required: true, authenticatorRequired: false, storeKeyFile: keyFile, smtp: SMTP_A });
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email', 'totp']);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c.challengeId);
    await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
    await expectOwnerError(finishChallenge(ctx, c.challengeId), 'OWNER_STEP_ORDER', 409);
    await verifyTotpStep(ctx, c.challengeId, totpCode(enrolled.totpSecret!));
    expect((await finishChallenge(ctx, c.challengeId)).ticket).toBeTruthy();
    expect(await ownerStatus(OWNER)).toMatchObject({ authenticator: true });
  });

  it('only an explicit `false` turns it off: a null, a string or an empty object still means required', () => {
    const base = { v: 1, accountId: OWNER, questions: [], email: { address: 'a@b.invalid', smtpFingerprint: 'x' }, recoveryCodes: [], createdAt: '', updatedAt: '' } as OwnerStoreDoc;
    expect(authenticatorRequired({ ...base })).toBe(true);
    expect(authenticatorRequired({ ...base, factors: {} as never })).toBe(true);
    expect(authenticatorRequired({ ...base, factors: { authenticator: null } as never })).toBe(true);
    expect(authenticatorRequired({ ...base, factors: { authenticator: 'false' } as never })).toBe(true);
    expect(authenticatorRequired({ ...base, factors: { authenticator: true } })).toBe(true);
    expect(authenticatorRequired({ ...base, factors: { authenticator: false } })).toBe(false);
  });

  it('an enrolment that requires the authenticator but holds no secret can never be completed', async () => {
    await rewriteDoc((doc) => {
      delete doc.totp;
    });
    const ctx = ctxOf('sessA');
    const id = await twoFactors(ctx);
    await expectOwnerError(finishChallenge(ctx, id), 'OWNER_STEP_ORDER', 409);
    await expectOwnerError(verifyTotpStep(ctx, id, totpCode(generateTotpSecret())), 'OWNER_STORE_UNREADABLE', 403);
    await expectOwnerError(finishChallenge(ctx, id), 'OWNER_STEP_ORDER', 409);
  });
});

describe('recovery re-enrolment (owner:recover repeats the enrolment)', () => {
  it('from with to without: the old authenticator and codes stop working and the run drops to two factors', async () => {
    await enrol(true);
    const old = enrolled;
    // one recovery code is spent in the old enrolment; a new enrolment starts with a clean list
    const before = await readStore();
    if (before.state !== 'ok') throw new Error('store');
    await pool.query('INSERT INTO owner_recovery_codes_used (code_id) VALUES ($1)', [before.doc.recoveryCodes[0]!.id]);
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM owner_recovery_codes_used')).rows[0].n).toBe(1);
    await enrol(false);
    expect((await pool.query('SELECT COUNT(*)::int AS n FROM owner_recovery_codes_used')).rows[0].n).toBe(0);
    const ctx = ctxOf('sessA');
    const c = await startChallenge(ctx, { operation: 'license.save', target: 'gms' });
    expect(c.steps.map((s) => s.id)).toEqual(['questions', 'email']);
    // the old answers no longer work
    await expectOwnerError(answerQuestions(ctx, c.challengeId, old.answers), 'OWNER_VERIFICATION_FAILED', 403);
    await answerQuestions(ctx, c.challengeId, enrolled.answers);
    await sendEmailCode(ctx, c.challengeId);
    await verifyEmailCode(ctx, c.challengeId, lastEmailCode());
    // the old authenticator is not accepted for the new enrolment
    await expectOwnerError(verifyTotpStep(ctx, c.challengeId, totpCode(old.totpSecret!)), 'OWNER_AUTHENTICATOR_NOT_USED', 409);
    expect((await finishChallenge(ctx, c.challengeId)).ticket).toBeTruthy();
    const store = await readStore();
    if (store.state !== 'ok') throw new Error('store');
    expect(store.doc.totp).toBeUndefined();
    expect(JSON.stringify(store.doc)).not.toContain(old.totpSecret!);
  });

  it('from without to with: the authenticator becomes required again', async () => {
    await enrol(false);
    await enrol(true);
    const store = await readStore();
    if (store.state !== 'ok') throw new Error('store');
    expect(store.doc.factors).toEqual({ authenticator: true });
    const ctx = ctxOf('sessA');
    const id = await twoFactors(ctx);
    await expectOwnerError(finishChallenge(ctx, id), 'OWNER_STEP_ORDER', 409);
    await verifyTotpStep(ctx, id, totpCode(enrolled.totpSecret!));
    expect((await finishChallenge(ctx, id)).ticket).toBeTruthy();
  });
});
