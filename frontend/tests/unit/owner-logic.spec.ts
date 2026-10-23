import { expect, test } from '@playwright/test';
import {
  answersProblem,
  attemptsText,
  codeProblem,
  currentStep,
  emailReasonText,
  flowReducer,
  formatCountdown,
  formatWait,
  initialFlowState,
  introSteps,
  mapFailure,
  parseRefusal,
  phraseOf,
  progressOf,
  recoveryCodesNote,
  secondsUntil,
  totpProblem,
  type FlowState,
  type StartData,
  type Step,
} from '../../shared/owner/ownerLogic';

const STEPS: Step[] = [
  { id: 'questions', done: false },
  { id: 'email', done: false },
  { id: 'totp', done: false },
];
const START: StartData = {
  challengeId: 'c1',
  operation: { key: 'keys.rotate', label: 'Rotate the signing key', warning: 'w' },
  questions: [{ index: 0, prompt: 'Q1' }, { index: 1, prompt: 'Q2' }, { index: 2, prompt: 'Q3' }],
  steps: STEPS,
  emailAvailable: true,
  expiresAt: '2030-01-01T00:00:00Z',
};
const NOW = 1_000_000;
const started = (over: Partial<StartData> = {}): FlowState =>
  flowReducer(flowReducer(initialFlowState(), { type: 'begin' }), { type: 'started', data: { ...START, ...over } });

test.describe('parseRefusal', () => {
  const body = (code: string, extra: object = {}) => ({
    error: { code, message: 'm', operation: 'keys.rotate', target: null, label: 'Rotate the signing key', warning: 'Careful', ...extra },
  });
  test('recognises the three owner refusals on a 403 only', () => {
    for (const code of ['OWNER_AUTHORISATION_REQUIRED', 'OWNER_AUTHORISATION_INVALID', 'OWNER_NOT_ENROLLED']) {
      expect(parseRefusal(403, body(code))?.code).toBe(code);
      expect(parseRefusal(401, body(code))).toBeNull();
    }
  });
  test('an ordinary 403 or a malformed body is not a refusal', () => {
    expect(parseRefusal(403, body('ERR-PLATFORM-ADMIN-ONLY'))).toBeNull();
    expect(parseRefusal(403, null)).toBeNull();
    expect(parseRefusal(403, { error: 'x' })).toBeNull();
  });
  test('carries operation, target, label and warning; fills gaps safely', () => {
    const r = parseRefusal(403, body('OWNER_AUTHORISATION_REQUIRED', { target: 'acme' }))!;
    expect(r).toMatchObject({ operation: 'keys.rotate', target: 'acme', label: 'Rotate the signing key', warning: 'Careful' });
    const bare = parseRefusal(403, { error: { code: 'OWNER_AUTHORISATION_REQUIRED' } })!;
    expect(bare.target).toBeNull();
    expect(bare.label.length).toBeGreaterThan(0);
  });
});

test.describe('mapFailure', () => {
  test('wrong answer shows the server text and the attempts left, once', () => {
    const f = mapFailure(403, 'OWNER_VERIFICATION_FAILED', 'That answer was not right.', { attemptsLeft: 2 });
    expect(f.kind).toBe('wrong');
    expect(f.message).toBe('That answer was not right. You have 2 attempts left.');
    expect(mapFailure(403, 'OWNER_VERIFICATION_FAILED', 'Only 1 attempt left.', { attemptsLeft: 1 }).message).toBe('Only 1 attempt left.');
    expect(mapFailure(403, 'OWNER_VERIFICATION_FAILED', 'No.', {}).message).toBe('No.');
  });
  test('lock reads the wait in words and carries the seconds', () => {
    const f = mapFailure(423, 'OWNER_VERIFICATION_LOCKED', '', { retryAfterSeconds: 90 });
    expect(f).toMatchObject({ kind: 'locked', retryAfterSeconds: 90 });
    expect(f.message).toContain('1 minute 30 seconds');
  });
  test('expired, not enrolled, email unavailable, session, network, validation', () => {
    expect(mapFailure(410, 'OWNER_CHALLENGE_EXPIRED', '').kind).toBe('expired');
    expect(mapFailure(403, 'OWNER_NOT_ENROLLED', '').kind).toBe('not-enrolled');
    const mail = mapFailure(409, 'OWNER_EMAIL_UNAVAILABLE', '', { recoveryCodeAvailable: true });
    expect(mail).toMatchObject({ kind: 'email-unavailable', recoveryCodeAvailable: true });
    expect(mail.message).toContain('recovery code');
    expect(mapFailure(409, 'OWNER_EMAIL_UNAVAILABLE', '', { recoveryCodeAvailable: false }).message).toContain('no offline recovery codes');
    expect(mapFailure(401, 'ERR-NOT-AUTHENTICATED', '').kind).toBe('session');
    expect(mapFailure(0, 'ERR-NETWORK', '').kind).toBe('network');
    expect(mapFailure(400, 'ERR-VALIDATION-FAILED', 'Bad value').message).toBe('Bad value');
    expect(mapFailure(500, 'X', '').message).toContain('500');
  });
  test('no user-facing text uses protocol words', () => {
    const all = [
      mapFailure(403, 'OWNER_NOT_ENROLLED', '').message,
      mapFailure(410, 'OWNER_CHALLENGE_EXPIRED', '').message,
      mapFailure(423, 'OWNER_VERIFICATION_LOCKED', '', { retryAfterSeconds: 5 }).message,
      mapFailure(409, 'OWNER_EMAIL_UNAVAILABLE', '').message,
      emailReasonText('smtp_changed'),
      emailReasonText('smtp_not_configured'),
      recoveryCodesNote(0).text,
    ].join(' ');
    expect(all).not.toMatch(/\b(JWT|TOTP|jti|ticket)\b/i);
  });
});

test.describe('formatting', () => {
  test('formatWait', () => {
    expect(formatWait(0)).toBe('0 seconds');
    expect(formatWait(1)).toBe('1 second');
    expect(formatWait(45)).toBe('45 seconds');
    expect(formatWait(60)).toBe('1 minute');
    expect(formatWait(300)).toBe('5 minutes');
    expect(formatWait(3600)).toBe('1 hour');
    expect(formatWait(5400)).toBe('1 hour 30 minutes');
  });
  test('formatCountdown', () => {
    expect(formatCountdown(0)).toBe('0:00');
    expect(formatCountdown(-5)).toBe('0:00');
    expect(formatCountdown(5)).toBe('0:05');
    expect(formatCountdown(299.2)).toBe('5:00');
    expect(formatCountdown(3723)).toBe('1:02:03');
  });
  test('secondsUntil never goes negative and rounds up', () => {
    expect(secondsUntil(10_500, 10_000)).toBe(1);
    expect(secondsUntil(10_000, 12_000)).toBe(0);
  });
  test('attemptsText and phraseOf', () => {
    expect(attemptsText(0)).toBe('No attempts are left.');
    expect(attemptsText(1)).toBe('You have 1 attempt left.');
    expect(phraseOf('Rotate the signing key')).toBe('rotate the signing key');
    expect(phraseOf('DMS tenant creation')).toBe('DMS tenant creation');
  });
  test('recovery code warnings', () => {
    expect(recoveryCodesNote(0).tone).toBe('danger');
    expect(recoveryCodesNote(2).tone).toBe('warning');
    expect(recoveryCodesNote(3).tone).toBe('success');
  });
});

test.describe('input checks', () => {
  test('answers, codes, authenticator digits', () => {
    expect(answersProblem(['a', 'b', 'c'])).toBeNull();
    expect(answersProblem(['a', ' ', 'c'])).not.toBeNull();
    expect(totpProblem('123456')).toBeNull();
    expect(totpProblem('12345')).not.toBeNull();
    expect(totpProblem('12345a')).not.toBeNull();
    expect(codeProblem('', 'a code')).not.toBeNull();
    expect(codeProblem('ABCD-1234', 'a code')).toBeNull();
  });
});

test.describe('flowReducer', () => {
  test('begins at the intro, or at not-enrolled when the server said so', () => {
    expect(initialFlowState().phase).toBe('intro');
    expect(initialFlowState(true).phase).toBe('not-enrolled');
  });
  test('start leads to the first step; email unavailable goes straight to recovery', () => {
    const s = started();
    expect(s.phase).toBe('steps');
    expect(currentStep(s.steps)).toBe('questions');
    expect(s.recoveryOffered).toBe(false);
    expect(started({ emailAvailable: false }).recoveryOffered).toBe(true);
  });
  test('steps advance in order and finish only when all are done', () => {
    let s = started();
    s = flowReducer(s, { type: 'steps', steps: [{ id: 'questions', done: true }, { id: 'email', done: false }, { id: 'totp', done: false }] });
    expect(currentStep(s.steps)).toBe('email');
    expect(progressOf(s.steps)).toMatchObject({ done: 1, total: 3, label: 'Step 2 of 3' });
    s = flowReducer(s, { type: 'steps', steps: STEPS.map((x) => ({ ...x, done: true })) });
    expect(currentStep(s.steps)).toBeNull();
    expect(progressOf(s.steps).label).toBe('All steps done');
  });
  test('an enrolment without the authenticator: two steps, finishes after the second, never shows an authenticator step', () => {
    const TWO: Step[] = [{ id: 'questions', done: false }, { id: 'email', done: false }];
    let s = started({ steps: TWO, authenticatorRequired: false });
    expect(s.steps.map((x) => x.id)).toEqual(['questions', 'email']);
    expect(progressOf(s.steps)).toMatchObject({ done: 0, total: 2, label: 'Step 1 of 2' });
    s = flowReducer(s, { type: 'steps', steps: [{ id: 'questions', done: true }, { id: 'email', done: false }] });
    expect(currentStep(s.steps)).toBe('email');
    expect(progressOf(s.steps).label).toBe('Step 2 of 2');
    s = flowReducer(s, { type: 'steps', steps: TWO.map((x) => ({ ...x, done: true })) });
    expect(currentStep(s.steps)).toBeNull();
    expect(progressOf(s.steps).label).toBe('All steps done');
  });
  test('the first screen never promises a step the server will not ask for', () => {
    expect(introSteps(true)).toMatch(/authenticator app./);
    expect(introSteps(false)).toMatch(/No authenticator app is needed/);
    expect(introSteps(false)).not.toMatch(/type a code from your authenticator/);
    expect(introSteps(null)).toMatch(/If your owner verification also uses an authenticator app/);
    for (const v of [true, false, null]) expect(introSteps(v)).not.toMatch(/(JWT|TOTP|jti|ticket)/i);
  });
  test('a mailed code is remembered; a 409 switches to recovery and drops it', () => {
    let s = flowReducer(started(), { type: 'email-sent', maskedAddress: 'o***@example.org', expiresInSeconds: 600 });
    expect(s.emailSent?.maskedAddress).toBe('o***@example.org');
    s = flowReducer(s, { type: 'failure', failure: mapFailure(409, 'OWNER_EMAIL_UNAVAILABLE', '', { recoveryCodeAvailable: true }), now: NOW });
    expect(s).toMatchObject({ recoveryOffered: true, recoveryCodeAvailable: true, emailSent: null, phase: 'steps' });
  });
  test('a wrong answer keeps the person on the step with a message', () => {
    const s = flowReducer(started(), { type: 'failure', failure: mapFailure(403, 'OWNER_VERIFICATION_FAILED', 'No.', { attemptsLeft: 1 }), now: NOW });
    expect(s.phase).toBe('steps');
    expect(s.busy).toBe(false);
    expect(s.error).toContain('1 attempt');
  });
  test('lock records when it ends', () => {
    const s = flowReducer(started(), { type: 'failure', failure: mapFailure(423, 'OWNER_VERIFICATION_LOCKED', '', { retryAfterSeconds: 120 }), now: NOW });
    expect(s.phase).toBe('locked');
    expect(s.lockedUntil).toBe(NOW + 120_000);
  });
  test('expiry and not-enrolled change the phase; restart goes back to the intro', () => {
    let s = flowReducer(started(), { type: 'failure', failure: mapFailure(410, 'OWNER_CHALLENGE_EXPIRED', ''), now: NOW });
    expect(s.phase).toBe('expired');
    s = flowReducer(s, { type: 'restart' });
    expect(s.phase).toBe('intro');
    expect(flowReducer(initialFlowState(), { type: 'failure', failure: mapFailure(403, 'OWNER_NOT_ENROLLED', ''), now: NOW }).phase).toBe('not-enrolled');
  });
  test('failing to start is "failed"; failing to finish returns to the steps', () => {
    const starting = flowReducer(initialFlowState(), { type: 'begin' });
    expect(flowReducer(starting, { type: 'failure', failure: mapFailure(500, 'X', ''), now: NOW }).phase).toBe('failed');
    const finishing = flowReducer(started(), { type: 'finishing' });
    expect(finishing.phase).toBe('finishing');
    expect(flowReducer(finishing, { type: 'failure', failure: mapFailure(500, 'X', ''), now: NOW }).phase).toBe('steps');
  });
  test('finishing stores the authorisation', () => {
    const ticket = { ticket: 't', expiresAt: 'x', operation: 'keys.rotate', audience: 'sso' as const };
    expect(flowReducer(flowReducer(started(), { type: 'finishing' }), { type: 'finished', ticket })).toMatchObject({ phase: 'done', ticket });
  });
});
