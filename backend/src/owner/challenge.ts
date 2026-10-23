/**
 * The owner verification sequence, enforced here and nowhere else (never in the frontend):
 *
 *   start -> questions -> (emailed code | recovery code when the email factor is unavailable) -> authenticator (only if the enrolment has one) -> finish -> one ticket
 *
 * Rules every step shares:
 *   - the run belongs to the portal session that started it (a hash) and to ONE operation; another session cannot continue it;
 *   - steps are strictly in order, each remembered in the database, so skipping one is impossible;
 *   - while the sequence is locked nothing is checked, and every wrong answer or code, in any step, counts toward the persistent lockout (limiter.ts);
 *   - a code that is spent (emailed code, recovery code, authenticator time step) is spent atomically, so it cannot be used twice, not even at the same instant;
 *   - NEVER fewer factors: if the emailed code cannot be used, an unused offline recovery code replaces it, and the questions are always required, and so is the
 *     authenticator for an enrolment made with one. The factors demanded are the ones RECORDED IN THE STORED ENROLMENT (store.ts `factors`), never the current
 *     OWNER_AUTHENTICATOR_REQUIRED, so changing that setting cannot weaken an existing enrolment. An enrolment without the authenticator has exactly two factors
 *     (questions + emailed or recovery code) and a TOTP code is never accepted for it;
 *   - nothing secret is logged or audited: not an answer, a code, the address, the secret or the ticket.
 */
import crypto from 'node:crypto';
import { verifyTotp } from '../auth/totp.js';
import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';
import { emitSecurityEvent } from '../ops/securityEvents.js';
import { ownerAudit } from './audit.js';
import { acceptTotpStep, lockStatus, recordFailure, recordRunSuccess } from './limiter.js';
import { codeMail, currentMailer, maskAddress } from './mailer.js';
import {
  CHALLENGE_TTL_SECONDS,
  EMAIL_CODE_DIGITS,
  EMAIL_CODE_MAX_ATTEMPTS,
  EMAIL_CODE_TTL_SECONDS,
  EMAIL_MAX_SENDS_PER_CHALLENGE,
  EMAIL_MAX_SENDS_PER_HOUR,
  EMAIL_RESEND_SECONDS,
  MAX_ANSWER_LENGTH,
  MAX_CHALLENGES_PER_HOUR,
  SECURITY_QUESTION_COUNT,
} from './policy.js';
import { verifyAllAnswers } from './questions.js';
import { findOperation, targetHash, type OwnerOperation } from './registry.js';
import { keyedHash, safeEqual } from './seal.js';
import { authenticatorRequired, emailAvailability, readStore, recoveryCodesRemaining, relayChangedSinceEnrolment, spendRecoveryCode, type OwnerStoreDoc } from './store.js';
import { issueTicket, purgeOldOwnerRows, type IssuedTicket } from './ticket.js';
import type { StoreKeys } from './seal.js';

/** The relay-changed notice is logged once per process, not on every code. */
let relayNoticeLogged = false;

/** An answer the HTTP layer sends as-is: status, machine code, plain-language message and optional extra fields. */
export class OwnerError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = 'OwnerError';
  }
}

export interface OwnerContext {
  accountId: string;
  sessionHash: string;
  /** Writes an entry in the tamper-evident admin audit chain (the router supplies it, because it needs the request). */
  chainAudit?: (action: string, detail: Record<string, unknown>) => Promise<void>;
}

interface Challenge {
  id: string;
  operation_key: string;
  target_hash: string | null;
  questions_ok_at: Date | null;
  second_kind: 'email' | 'recovery' | null;
  second_ok_at: Date | null;
  totp_ok_at: Date | null;
  email_code_hash: string | null;
  email_code_expires_at: Date | null;
  email_attempts: number;
  email_sends: number;
  last_email_sent_at: Date | null;
  email_failed: boolean;
  expires_at: Date;
}

export interface StepState {
  id: 'questions' | 'email' | 'totp';
  done: boolean;
}

/** The steps of a run: the authenticator step exists only when the stored enrolment includes the authenticator. */
const stepsOf = (c: Pick<Challenge, 'questions_ok_at' | 'second_ok_at' | 'totp_ok_at'>, doc: OwnerStoreDoc): StepState[] => {
  const steps: StepState[] = [
    { id: 'questions', done: Boolean(c.questions_ok_at) },
    { id: 'email', done: Boolean(c.second_ok_at) },
  ];
  if (authenticatorRequired(doc)) steps.push({ id: 'totp', done: Boolean(c.totp_ok_at) });
  return steps;
};

const FAILED_MESSAGE = 'That did not match. Check it and try again.';

/** Open the store for this owner, or say precisely why not. Also refuses while locked. */
async function openOwner(ctx: OwnerContext): Promise<{ doc: OwnerStoreDoc; keys: StoreKeys }> {
  const store = await readStore();
  if (store.state === 'none') {
    throw new OwnerError(403, 'OWNER_NOT_ENROLLED', 'Owner verification has not been set up yet. The owner must enrol at a terminal on the server first (see the SSO operations guide).');
  }
  if (store.state === 'unreadable') {
    logger.error({ reason: store.reason }, '[idp:owner:ALERT] the owner store cannot be opened; owner-only operations are refused');
    throw new OwnerError(403, 'OWNER_STORE_UNREADABLE', 'Owner verification cannot be read on this server (its key file is missing or does not match). Owner-only operations are refused until it is repaired.', { reason: store.reason });
  }
  if (store.doc.accountId !== ctx.accountId) {
    throw new OwnerError(403, 'OWNER_NOT_ENROLLED', 'Owner verification has not been set up for this account.');
  }
  const lock = await lockStatus();
  if (lock.locked) throw lockedError(lock.retryAfterSeconds);
  return { doc: store.doc, keys: store.keys };
}

const lockedError = (retryAfterSeconds: number): OwnerError =>
  new OwnerError(423, 'OWNER_VERIFICATION_LOCKED', 'Too many wrong attempts. Owner verification is locked for now. Wait and try again, or ask whoever runs the server.', { retryAfterSeconds });

/** Count a wrong answer or code and throw the right answer for it. */
async function failed(ctx: OwnerContext, c: Challenge, step: string, message = FAILED_MESSAGE): Promise<never> {
  const result = await recordFailure();
  const operation = c.operation_key;
  emitSecurityEvent({
    kind: 'owner_verification_failed',
    severity: result.locked ? 'critical' : 'warning',
    actor: { userId: ctx.accountId, sessionId: ctx.sessionHash.slice(0, 8) },
    operation,
    detail: { step, attemptsLeft: result.attemptsLeft, locked: result.locked },
  });
  await ownerAudit('step_failed', result.locked ? 'locked' : 'failed', { operation, sessionHash: ctx.sessionHash, detail: { step, attemptsLeft: result.attemptsLeft } });
  if (result.locked) {
    emitSecurityEvent({
      kind: 'owner_verification_locked',
      severity: 'critical',
      actor: { userId: ctx.accountId, sessionId: ctx.sessionHash.slice(0, 8) },
      operation,
      detail: { retryAfterSeconds: result.retryAfterSeconds },
    });
    await ownerAudit('locked', 'locked', { operation, sessionHash: ctx.sessionHash, detail: { retryAfterSeconds: result.retryAfterSeconds } });
    await ctx.chainAudit?.('owner.verification.locked', { operation, retryAfterSeconds: result.retryAfterSeconds }).catch(() => undefined);
    throw lockedError(result.retryAfterSeconds);
  }
  throw new OwnerError(403, 'OWNER_VERIFICATION_FAILED', message, { attemptsLeft: result.attemptsLeft });
}

async function loadChallenge(ctx: OwnerContext, id: string): Promise<Challenge> {
  const gone = () => new OwnerError(410, 'OWNER_CHALLENGE_EXPIRED', 'This check has expired. Start again from the first step.');
  if (!/^[0-9a-f-]{36}$/i.test(String(id))) throw gone();
  const { rows } = await pool.query<Challenge>(
    `SELECT id, operation_key, target_hash, questions_ok_at, second_kind, second_ok_at, totp_ok_at, email_code_hash, email_code_expires_at,
            email_attempts, email_sends, last_email_sent_at, email_failed, expires_at
       FROM owner_verification_challenges
      WHERE id = $1 AND session_hash = $2 AND account_id = $3 AND finished_at IS NULL AND expires_at > NOW()`,
    [id, ctx.sessionHash, ctx.accountId],
  );
  if (!rows[0]) throw gone();
  return rows[0];
}

const order = (message: string): OwnerError => new OwnerError(409, 'OWNER_STEP_ORDER', message);

export async function startChallenge(ctx: OwnerContext, input: { operation: string; target?: string }) {
  const op: OwnerOperation | undefined = findOperation(String(input.operation ?? ''));
  if (!op || op.cli) throw new OwnerError(404, 'ERR-NOT-FOUND', 'Not found');
  const target = typeof input.target === 'string' ? input.target.slice(0, 300) : '';
  if (op.needsTarget && !target) throw new OwnerError(400, 'ERR-VALIDATION-FAILED', 'This action needs to say what it is for.');
  const { doc } = await openOwner(ctx);

  const { rows: recent } = await pool.query<{ n: number }>(`SELECT COUNT(*)::int AS n FROM owner_verification_challenges WHERE created_at > NOW() - INTERVAL '1 hour'`);
  if ((recent[0]?.n ?? 0) >= MAX_CHALLENGES_PER_HOUR) {
    throw new OwnerError(429, 'OWNER_RATE_LIMITED', 'Too many verifications were started in the last hour. Wait a while and try again.');
  }
  purgeOldOwnerRows().catch(() => undefined);
  // One active run per session.
  await pool.query('DELETE FROM owner_verification_challenges WHERE session_hash = $1 AND finished_at IS NULL', [ctx.sessionHash]);
  const id = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000);
  await pool.query(
    'INSERT INTO owner_verification_challenges (id, session_hash, account_id, operation_key, target_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6)',
    [id, ctx.sessionHash, ctx.accountId, op.key, targetHash(op.key, target), expiresAt],
  );
  await ownerAudit('challenge_started', 'info', { operation: op.key, sessionHash: ctx.sessionHash });
  const availability = emailAvailability(doc);
  return {
    challengeId: id,
    operation: { key: op.key, label: op.label, warning: op.warning },
    questions: doc.questions.map((q, index) => ({ index, prompt: q.prompt })),
    steps: stepsOf({ questions_ok_at: null, second_ok_at: null, totp_ok_at: null }, doc),
    authenticatorRequired: authenticatorRequired(doc),
    emailAvailable: availability.available,
    emailUnavailableReason: availability.reason,
    recoveryCodeAvailable: (await recoveryCodesRemaining(doc)) > 0,
    expiresAt: expiresAt.toISOString(),
  };
}

export async function answerQuestions(ctx: OwnerContext, id: string, answers: unknown) {
  const { doc, keys } = await openOwner(ctx);
  const c = await loadChallenge(ctx, id);
  if (!Array.isArray(answers) || answers.length !== SECURITY_QUESTION_COUNT || answers.some((a) => typeof a !== 'string' || a.length > MAX_ANSWER_LENGTH)) {
    throw new OwnerError(400, 'ERR-VALIDATION-FAILED', `Answer all ${SECURITY_QUESTION_COUNT} questions.`);
  }
  if (c.questions_ok_at) return { steps: stepsOf(c, doc) };
  const ok = await verifyAllAnswers(keys, answers as string[], doc.questions.map((q) => q.hash));
  if (!ok) await failed(ctx, c, 'questions');
  await pool.query('UPDATE owner_verification_challenges SET questions_ok_at = NOW() WHERE id = $1 AND questions_ok_at IS NULL', [c.id]);
  await ownerAudit('questions_ok', 'ok', { operation: c.operation_key, sessionHash: ctx.sessionHash });
  return { steps: stepsOf({ ...c, questions_ok_at: new Date() }, doc) };
}

export async function sendEmailCode(ctx: OwnerContext, id: string) {
  const { doc, keys } = await openOwner(ctx);
  const c = await loadChallenge(ctx, id);
  if (!c.questions_ok_at) throw order('Answer the security questions first.');
  if (c.second_ok_at) throw order('This step is already done.');
  const unavailable = async (): Promise<never> => {
    throw new OwnerError(409, 'OWNER_EMAIL_UNAVAILABLE', 'The emailed code cannot be used right now. Use one of your offline recovery codes instead.', {
      recoveryCodeAvailable: (await recoveryCodesRemaining(doc)) > 0,
    });
  };
  if (!emailAvailability(doc).available) return unavailable();
  if (c.email_sends >= EMAIL_MAX_SENDS_PER_CHALLENGE) throw new OwnerError(429, 'OWNER_RATE_LIMITED', 'The code was already sent as many times as allowed. Start again.');
  if (c.last_email_sent_at && Date.now() - new Date(c.last_email_sent_at).getTime() < EMAIL_RESEND_SECONDS * 1000) {
    throw new OwnerError(429, 'OWNER_RATE_LIMITED', `Wait ${EMAIL_RESEND_SECONDS} seconds before asking for another code.`, { retryAfterSeconds: EMAIL_RESEND_SECONDS });
  }
  const { rows: hour } = await pool.query<{ n: number }>(`SELECT COALESCE(SUM(email_sends), 0)::int AS n FROM owner_verification_challenges WHERE created_at > NOW() - INTERVAL '1 hour'`);
  if ((hour[0]?.n ?? 0) >= EMAIL_MAX_SENDS_PER_HOUR) throw new OwnerError(429, 'OWNER_RATE_LIMITED', 'Too many codes were sent in the last hour. Wait a while, or use a recovery code.');

  const code = String(crypto.randomInt(0, 10 ** EMAIL_CODE_DIGITS)).padStart(EMAIL_CODE_DIGITS, '0');
  await pool.query(
    `UPDATE owner_verification_challenges
        SET email_code_hash = $2, email_code_expires_at = NOW() + make_interval(secs => $3), email_attempts = 0,
            email_sends = email_sends + 1, last_email_sent_at = NOW()
      WHERE id = $1`,
    [c.id, keyedHash(keys, 'email', c.id, code), EMAIL_CODE_TTL_SECONDS],
  );
  try {
    const op = findOperation(c.operation_key);
    if (!relayNoticeLogged && relayChangedSinceEnrolment(doc)) {
      relayNoticeLogged = true;
      logger.warn('[idp:owner:NOTICE] the mail relay (SMTP_*) differs from the one recorded at enrolment; the emailed code now goes through the relay configured here');
    }
    await currentMailer().send(codeMail(doc.email.address, code, op?.label ?? c.operation_key, Math.round(EMAIL_CODE_TTL_SECONDS / 60)));
  } catch (err) {
    // The code was never delivered: void it, remember the email factor failed in this run (which is what allows a recovery code), say nothing about why.
    await pool.query('UPDATE owner_verification_challenges SET email_code_hash = NULL, email_failed = TRUE WHERE id = $1', [c.id]);
    logger.error({ errName: (err as Error)?.name, errCode: (err as { code?: string })?.code }, '[idp:owner:ALERT] the owner verification email could not be sent');
    await ownerAudit('email_send_failed', 'failed', { operation: c.operation_key, sessionHash: ctx.sessionHash });
    return unavailable();
  }
  await ownerAudit('email_code_sent', 'ok', { operation: c.operation_key, sessionHash: ctx.sessionHash });
  return { sent: true, expiresInSeconds: EMAIL_CODE_TTL_SECONDS, maskedAddress: maskAddress(doc.email.address) };
}

export async function verifyEmailCode(ctx: OwnerContext, id: string, code: unknown) {
  const { doc, keys } = await openOwner(ctx);
  const c = await loadChallenge(ctx, id);
  if (!c.questions_ok_at) throw order('Answer the security questions first.');
  if (c.second_ok_at) return { steps: stepsOf(c, doc) };
  if (typeof code !== 'string' || !/^\d{4,12}$/.test(code.replace(/\s+/g, ''))) throw new OwnerError(400, 'ERR-VALIDATION-FAILED', 'Type the code from the email.');
  if (!c.email_code_hash || !c.email_code_expires_at) throw new OwnerError(409, 'OWNER_EMAIL_CODE_NOT_SENT', 'No code is waiting. Ask for a new one.');
  if (new Date(c.email_code_expires_at).getTime() < Date.now()) {
    await pool.query('UPDATE owner_verification_challenges SET email_code_hash = NULL WHERE id = $1', [c.id]);
    throw new OwnerError(410, 'OWNER_EMAIL_CODE_EXPIRED', 'That code has expired. Ask for a new one.');
  }
  // Count the attempt before comparing, atomically, so parallel guesses cannot exceed the limit.
  const { rows } = await pool.query<{ email_code_hash: string }>(
    'UPDATE owner_verification_challenges SET email_attempts = email_attempts + 1 WHERE id = $1 AND email_attempts < $2 AND email_code_hash IS NOT NULL RETURNING email_code_hash',
    [c.id, EMAIL_CODE_MAX_ATTEMPTS],
  );
  if (!rows[0]) {
    await pool.query('UPDATE owner_verification_challenges SET email_code_hash = NULL WHERE id = $1', [c.id]);
    return failed(ctx, c, 'email', 'Too many wrong tries on that code. Ask for a new one.');
  }
  const submitted = keyedHash(keys, 'email', c.id, code.replace(/\s+/g, ''));
  if (!safeEqual(submitted, rows[0].email_code_hash)) return failed(ctx, c, 'email');
  // Single use: only one request can clear the stored hash.
  const spent = await pool.query(
    `UPDATE owner_verification_challenges SET email_code_hash = NULL, second_kind = 'email', second_ok_at = NOW()
      WHERE id = $1 AND email_code_hash IS NOT NULL AND second_ok_at IS NULL`,
    [c.id],
  );
  if (spent.rowCount !== 1) return failed(ctx, c, 'email');
  await ownerAudit('email_code_ok', 'ok', { operation: c.operation_key, sessionHash: ctx.sessionHash });
  return { steps: stepsOf({ ...c, second_ok_at: new Date() }, doc) };
}

export async function verifyRecoveryCode(ctx: OwnerContext, id: string, code: unknown) {
  const { doc, keys } = await openOwner(ctx);
  const c = await loadChallenge(ctx, id);
  if (!c.questions_ok_at) throw order('Answer the security questions first.');
  if (c.second_ok_at) return { steps: stepsOf(c, doc) };
  // A recovery code REPLACES the emailed code; it is never an alternative to it while the email factor works.
  if (emailAvailability(doc).available && !c.email_failed) {
    throw new OwnerError(409, 'OWNER_RECOVERY_NOT_ALLOWED', 'The emailed code is available, so use it. Recovery codes are only for when email cannot be used.');
  }
  if (typeof code !== 'string' || code.length > 64) throw new OwnerError(400, 'ERR-VALIDATION-FAILED', 'Type one of your recovery codes.');
  const result = await spendRecoveryCode(keys, doc, code);
  if (result !== 'ok') return failed(ctx, c, 'recovery', result === 'used' ? 'That recovery code was already used.' : FAILED_MESSAGE);
  await pool.query(`UPDATE owner_verification_challenges SET second_kind = 'recovery', second_ok_at = NOW() WHERE id = $1 AND second_ok_at IS NULL`, [c.id]);
  await ownerAudit('recovery_code_used', 'ok', { operation: c.operation_key, sessionHash: ctx.sessionHash, detail: { remaining: await recoveryCodesRemaining(doc) } });
  return { steps: stepsOf({ ...c, second_ok_at: new Date() }, doc) };
}

export async function verifyTotpStep(ctx: OwnerContext, id: string, code: unknown) {
  const { doc } = await openOwner(ctx);
  const c = await loadChallenge(ctx, id);
  // An enrolment made without the authenticator has no secret to check: a code is refused outright (never accepted, never stored) and does not count as a guess.
  if (!authenticatorRequired(doc)) {
    throw new OwnerError(409, 'OWNER_AUTHENTICATOR_NOT_USED', 'This owner verification does not use an authenticator app. Nothing more is needed here.');
  }
  if (!c.questions_ok_at || !c.second_ok_at) throw order('Do the earlier steps first.');
  if (c.totp_ok_at) return { steps: stepsOf(c, doc) };
  // Fail closed: an enrolment that requires the authenticator but holds no secret can never be satisfied.
  if (!doc.totp?.secret) throw new OwnerError(403, 'OWNER_STORE_UNREADABLE', 'Owner verification cannot be read on this server. Owner-only operations are refused until it is repaired.', { reason: 'corrupt' });
  if (typeof code !== 'string' || !/^\d{6}$/.test(code.replace(/\s+/g, ''))) throw new OwnerError(400, 'ERR-VALIDATION-FAILED', 'Type the 6-digit code from your authenticator app.');
  const step = verifyTotp(doc.totp.secret, code);
  // A wrong code, and a right code that was already used (a replay), look the same to the caller.
  if (step === null || !(await acceptTotpStep(step))) return failed(ctx, c, 'totp');
  await pool.query('UPDATE owner_verification_challenges SET totp_ok_at = NOW() WHERE id = $1 AND totp_ok_at IS NULL', [c.id]);
  await ownerAudit('totp_ok', 'ok', { operation: c.operation_key, sessionHash: ctx.sessionHash });
  return { steps: stepsOf({ ...c, totp_ok_at: new Date() }, doc) };
}

export async function finishChallenge(ctx: OwnerContext, id: string): Promise<IssuedTicket & { operation: string; audience: 'sso' | 'dms' }> {
  const { doc } = await openOwner(ctx);
  const c = await loadChallenge(ctx, id);
  const needsAuthenticator = authenticatorRequired(doc);
  if (!c.questions_ok_at || !c.second_ok_at || (needsAuthenticator && !c.totp_ok_at)) throw order('Complete every step first.');
  const op = findOperation(c.operation_key);
  if (!op) throw new OwnerError(404, 'ERR-NOT-FOUND', 'Not found');
  // Exactly one finish per run.
  const done = await pool.query('UPDATE owner_verification_challenges SET finished_at = NOW() WHERE id = $1 AND finished_at IS NULL', [c.id]);
  if (done.rowCount !== 1) throw new OwnerError(410, 'OWNER_CHALLENGE_EXPIRED', 'This check has expired. Start again from the first step.');
  const issued = await issueTicket({ accountId: ctx.accountId, sessionHash: ctx.sessionHash, operation: op.key, targetHash: c.target_hash, audience: op.audience });
  await recordRunSuccess();
  await ownerAudit('ticket_issued', 'ok', { operation: op.key, sessionHash: ctx.sessionHash, detail: { audience: op.audience, via: c.second_kind, authenticator: needsAuthenticator ? 'used' : 'not used' } });
  await ctx.chainAudit?.('owner.verification.ticket_issued', { operation: op.key, audience: op.audience, secondFactor: c.second_kind ?? '', authenticator: needsAuthenticator ? 'used' : 'not used' }).catch(() => undefined);
  return { ...issued, operation: op.key, audience: op.audience };
}

/** The read-only status the page and the dialog use. Reveals no secret and nothing about the answers. */
export async function ownerStatus(accountId: string) {
  const store = await readStore();
  const lock = await lockStatus();
  const base = { locked: lock.locked, lockedUntil: lock.lockedUntil ? lock.lockedUntil.toISOString() : null };
  if (store.state === 'none') {
    return { enrolled: false, authenticator: null as boolean | null, emailAvailable: false, emailUnavailableReason: null as string | null, recoveryCodesRemaining: 0, storeProblem: null as string | null, ...base };
  }
  if (store.state === 'unreadable') {
    return { enrolled: false, authenticator: null as boolean | null, emailAvailable: false, emailUnavailableReason: null as string | null, recoveryCodesRemaining: 0, storeProblem: store.reason as string | null, ...base };
  }
  const availability = emailAvailability(store.doc);
  return {
    enrolled: store.doc.accountId === accountId,
    /** Whether the stored enrolment uses the authenticator (null when nothing readable is enrolled for this account). */
    authenticator: (store.doc.accountId === accountId ? authenticatorRequired(store.doc) : null) as boolean | null,
    emailAvailable: availability.available,
    emailUnavailableReason: availability.reason as string | null,
    recoveryCodesRemaining: await recoveryCodesRemaining(store.doc),
    storeProblem: null as string | null,
    ...base,
  };
}
