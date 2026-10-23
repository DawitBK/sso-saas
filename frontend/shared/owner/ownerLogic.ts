/**
 * Owner verification: the pure logic (no React, no fetch), so it can be unit-tested on its own.
 *
 * The server decides which actions are owner-only and checks the proof; everything here is presentation: what a refusal means,
 * which step comes next, how an error is worded, how a countdown reads. User-facing words stay plain: "security questions",
 * "emailed code", "authenticator app code", "recovery code", "authorisation". Never the protocol words.
 */

export const OWNER_BASE = '/api/v1/owner/verification';
export const OWNER_HEADER = 'X-Owner-Authorisation';

export type StepId = 'questions' | 'email' | 'totp';
export type Audience = 'sso' | 'dms';

export interface Step { id: StepId; done: boolean }
export interface Question { index: number; prompt: string }
export interface OperationInfo { key: string; label: string; warning: string }

export interface Ticket {
  ticket: string;
  expiresAt: string;
  operation: string;
  audience: Audience;
}

export interface StartData {
  challengeId: string;
  operation: OperationInfo;
  questions: Question[];
  steps: Step[];
  /** False when the owner's enrolment was made without the authenticator: the run has no authenticator step. Older servers omit it (read: true). */
  authenticatorRequired?: boolean;
  emailAvailable: boolean;
  expiresAt: string;
}

export interface OperationEntry extends OperationInfo { audience: Audience; needsTarget: boolean }

export interface OwnerStatus {
  required: boolean;
  enrolled: boolean;
  /** Whether the stored enrolment uses the authenticator app; null when nothing is enrolled; absent on an older server (read: true). */
  authenticator?: boolean | null;
  emailAvailable: boolean;
  emailUnavailableReason: null | 'smtp_not_configured' | 'smtp_changed';
  recoveryCodesRemaining: number;
  locked: boolean;
  lockedUntil: string | null;
  operations: OperationEntry[];
  csrf: string;
}

// ---------------------------------------------------------------------------------------------------------------------
// A refused owner-only request
// ---------------------------------------------------------------------------------------------------------------------

export type RefusalCode = 'OWNER_AUTHORISATION_REQUIRED' | 'OWNER_AUTHORISATION_INVALID' | 'OWNER_NOT_ENROLLED';

export interface Refusal {
  code: RefusalCode;
  operation: string;
  target: string | null;
  label: string;
  warning: string;
  message: string;
}

const REFUSAL_CODES: readonly string[] = ['OWNER_AUTHORISATION_REQUIRED', 'OWNER_AUTHORISATION_INVALID', 'OWNER_NOT_ENROLLED'];

/** Reads a refused response's JSON. Anything that is not one of the three owner refusals answers null (an ordinary 403 stays an ordinary 403). */
export function parseRefusal(status: number, body: unknown): Refusal | null {
  if (status !== 403 || typeof body !== 'object' || body === null) return null;
  const err = (body as { error?: unknown }).error;
  if (typeof err !== 'object' || err === null) return null;
  const e = err as Record<string, unknown>;
  if (typeof e.code !== 'string' || !REFUSAL_CODES.includes(e.code)) return null;
  const operation = typeof e.operation === 'string' ? e.operation : '';
  return {
    code: e.code as RefusalCode,
    operation,
    target: typeof e.target === 'string' ? e.target : null,
    label: typeof e.label === 'string' && e.label.trim() ? e.label : 'an action reserved to the owner',
    warning: typeof e.warning === 'string' ? e.warning : '',
    message: typeof e.message === 'string' ? e.message : '',
  };
}

// ---------------------------------------------------------------------------------------------------------------------
// Errors from the verification endpoints, in plain words
// ---------------------------------------------------------------------------------------------------------------------

export type FailureKind = 'wrong' | 'locked' | 'expired' | 'not-enrolled' | 'email-unavailable' | 'session' | 'network' | 'invalid' | 'other';

export interface Failure {
  kind: FailureKind;
  message: string;
  attemptsLeft: number | null;
  retryAfterSeconds: number | null;
  recoveryCodeAvailable: boolean | null;
}

export const NOT_ENROLLED_TEXT =
  'Owner verification has not been set up yet, so this action cannot be authorised. The server operator must run the enrolment tool on the server (see the Owner verification page and the SSO operations guide). Nothing was changed.';

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** "5 minutes", "1 minute 30 seconds", "45 seconds": a wait in words. */
export function formatWait(totalSeconds: number): string {
  const s = Math.max(0, Math.ceil(totalSeconds));
  if (s < 60) return `${s} ${s === 1 ? 'second' : 'seconds'}`;
  if (s < 3600) {
    const m = Math.floor(s / 60);
    const rest = s % 60;
    const minutes = `${m} ${m === 1 ? 'minute' : 'minutes'}`;
    return rest === 0 ? minutes : `${minutes} ${rest} ${rest === 1 ? 'second' : 'seconds'}`;
  }
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const hours = `${h} ${h === 1 ? 'hour' : 'hours'}`;
  return m === 0 ? hours : `${hours} ${m} ${m === 1 ? 'minute' : 'minutes'}`;
}

/** "4:05" (or "1:02:03"): a live countdown. */
export function formatCountdown(totalSeconds: number): string {
  const s = Math.max(0, Math.ceil(totalSeconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const two = (n: number) => String(n).padStart(2, '0');
  return h > 0 ? `${h}:${two(m)}:${two(sec)}` : `${m}:${two(sec)}`;
}

/** Whole seconds from `nowMs` until `untilMs`, never negative. */
export function secondsUntil(untilMs: number, nowMs: number): number {
  return Math.max(0, Math.ceil((untilMs - nowMs) / 1000));
}

export function attemptsText(n: number): string {
  if (n <= 0) return 'No attempts are left.';
  return n === 1 ? 'You have 1 attempt left.' : `You have ${n} attempts left.`;
}

export function lockedText(retryAfterSeconds: number | null): string {
  return retryAfterSeconds === null || retryAfterSeconds <= 0
    ? 'Too many wrong answers. Owner verification is locked for a while.'
    : `Too many wrong answers. Owner verification is locked. Try again in ${formatWait(retryAfterSeconds)}.`;
}

/** Maps a failed call to what the dialog should do and say. `extras` is the server's whole `error` object. */
export function mapFailure(status: number, code: string, message: string, extras: Record<string, unknown> = {}): Failure {
  const base = { attemptsLeft: num(extras.attemptsLeft), retryAfterSeconds: num(extras.retryAfterSeconds), recoveryCodeAvailable: typeof extras.recoveryCodeAvailable === 'boolean' ? extras.recoveryCodeAvailable : null };
  if (code === 'OWNER_VERIFICATION_LOCKED' || status === 423) return { ...base, kind: 'locked', message: lockedText(base.retryAfterSeconds) };
  if (code === 'OWNER_CHALLENGE_EXPIRED' || status === 410) {
    return { ...base, kind: 'expired', message: 'This verification took too long and has expired. Nothing was changed. Start again.' };
  }
  if (code === 'OWNER_NOT_ENROLLED') return { ...base, kind: 'not-enrolled', message: NOT_ENROLLED_TEXT };
  if (code === 'OWNER_EMAIL_UNAVAILABLE') {
    return {
      ...base,
      kind: 'email-unavailable',
      message: base.recoveryCodeAvailable === false
        ? 'The emailed code could not be sent, and no offline recovery codes are left. The server operator must make new ones (see the Owner verification page).'
        : 'The emailed code could not be sent. Use one of your offline recovery codes instead.',
    };
  }
  if (code === 'OWNER_VERIFICATION_FAILED') {
    const said = message.trim() || 'That was not correct.';
    return { ...base, kind: 'wrong', message: base.attemptsLeft !== null && !/attempt/i.test(said) ? `${said} ${attemptsText(base.attemptsLeft)}` : said };
  }
  if (status === 401) return { ...base, kind: 'session', message: 'Your session has ended. Sign in again, then try again.' };
  if (code === 'ERR-NETWORK' || status === 0) return { ...base, kind: 'network', message: 'Could not reach the server. Check your connection and try again.' };
  if (status === 400) return { ...base, kind: 'invalid', message: message.trim() || 'Please check what you entered.' };
  if (status === 404) return { ...base, kind: 'other', message: 'This action is not available to you.' };
  return { ...base, kind: 'other', message: message.trim() || `Something went wrong (HTTP ${status}). Try again.` };
}

// ---------------------------------------------------------------------------------------------------------------------
// The dialog's step machine
// ---------------------------------------------------------------------------------------------------------------------

export type Phase = 'intro' | 'starting' | 'steps' | 'finishing' | 'done' | 'locked' | 'expired' | 'not-enrolled' | 'failed';

export interface FlowState {
  phase: Phase;
  challengeId: string | null;
  operation: OperationInfo | null;
  questions: Question[];
  steps: Step[];
  emailAvailable: boolean;
  /** Set once a code has been mailed; the masked address is all the server reveals. */
  emailSent: { maskedAddress: string; expiresInSeconds: number } | null;
  /** The recovery-code field replaces the emailed-code field. */
  recoveryOffered: boolean;
  recoveryCodeAvailable: boolean | null;
  busy: boolean;
  error: string | null;
  lockedUntil: number | null;
  ticket: Ticket | null;
}

export type FlowAction =
  | { type: 'begin' }
  | { type: 'started'; data: StartData }
  | { type: 'busy' }
  | { type: 'steps'; steps: Step[] }
  | { type: 'email-sent'; maskedAddress: string; expiresInSeconds: number }
  | { type: 'finishing' }
  | { type: 'finished'; ticket: Ticket }
  | { type: 'failure'; failure: Failure; now: number }
  | { type: 'restart' };

export function initialFlowState(notEnrolled = false): FlowState {
  return {
    phase: notEnrolled ? 'not-enrolled' : 'intro',
    challengeId: null,
    operation: null,
    questions: [],
    steps: [],
    emailAvailable: true,
    emailSent: null,
    recoveryOffered: false,
    recoveryCodeAvailable: null,
    busy: false,
    error: notEnrolled ? NOT_ENROLLED_TEXT : null,
    lockedUntil: null,
    ticket: null,
  };
}

/** The first step not yet done, or null when every step is done and the owner may authorise. */
export function currentStep(steps: Step[]): StepId | null {
  return steps.find((s) => !s.done)?.id ?? null;
}

export function progressOf(steps: Step[]): { done: number; total: number; label: string } {
  const done = steps.filter((s) => s.done).length;
  const total = steps.length;
  const label = done >= total ? 'All steps done' : `Step ${done + 1} of ${total}`;
  return { done, total, label };
}

/**
 * What the dialog's first screen says will be asked, from what the server reports about the owner's enrolment (null: not known yet).
 * Never promises an authenticator step that the server will not ask for.
 */
export function introSteps(authenticator: boolean | null): string {
  if (authenticator === true) return 'You will answer your security questions, type a code sent to your mailbox, and type a code from your authenticator app.';
  if (authenticator === false) return 'You will answer your security questions and type a code sent to your mailbox. No authenticator app is needed.';
  return 'You will answer your security questions and type a code sent to your mailbox. If your owner verification also uses an authenticator app, you will be asked for its code last.';
}

export function stepLabel(id: StepId, recoveryOffered: boolean): string {
  if (id === 'questions') return 'Your security questions';
  if (id === 'email') return recoveryOffered ? 'An offline recovery code' : 'A code sent to your mailbox';
  return 'Your authenticator app code';
}

export function flowReducer(state: FlowState, action: FlowAction): FlowState {
  switch (action.type) {
    case 'begin':
      return { ...state, phase: 'starting', busy: true, error: null };
    case 'busy':
      return { ...state, busy: true, error: null };
    case 'started':
      return {
        ...initialFlowState(),
        phase: 'steps',
        challengeId: action.data.challengeId,
        operation: action.data.operation,
        questions: action.data.questions,
        steps: action.data.steps,
        emailAvailable: action.data.emailAvailable,
        recoveryOffered: !action.data.emailAvailable,
      };
    case 'steps':
      return { ...state, steps: action.steps, busy: false, error: null };
    case 'email-sent':
      return { ...state, emailSent: { maskedAddress: action.maskedAddress, expiresInSeconds: action.expiresInSeconds }, busy: false, error: null };
    case 'finishing':
      return { ...state, phase: 'finishing', busy: true, error: null };
    case 'finished':
      return { ...state, phase: 'done', busy: false, error: null, ticket: action.ticket };
    case 'restart':
      return initialFlowState();
    case 'failure': {
      const f = action.failure;
      if (f.kind === 'locked') {
        return { ...state, phase: 'locked', busy: false, error: f.message, lockedUntil: f.retryAfterSeconds !== null ? action.now + f.retryAfterSeconds * 1000 : action.now };
      }
      if (f.kind === 'expired') return { ...state, phase: 'expired', busy: false, error: f.message };
      if (f.kind === 'not-enrolled') return { ...state, phase: 'not-enrolled', busy: false, error: f.message };
      if (f.kind === 'email-unavailable') {
        return { ...state, emailSent: null, recoveryOffered: true, recoveryCodeAvailable: f.recoveryCodeAvailable, busy: false, error: f.message };
      }
      // A failure while starting has no steps to fall back to; any other failure leaves the person where they were.
      if (state.phase === 'starting') return { ...state, phase: 'failed', busy: false, error: f.message };
      if (state.phase === 'finishing') return { ...state, phase: 'steps', busy: false, error: f.message };
      return { ...state, busy: false, error: f.message };
    }
    default:
      return state;
  }
}

// ---------------------------------------------------------------------------------------------------------------------
// Checking what was typed (the server is the authority; this only catches the obvious before a wrong attempt is spent)
// ---------------------------------------------------------------------------------------------------------------------

export function answersProblem(answers: string[]): string | null {
  return answers.some((a) => a.trim() === '') ? 'Answer all three questions.' : null;
}

export function totpProblem(code: string): string | null {
  return /^\d{6}$/.test(code.trim()) ? null : 'Enter the 6 digits shown in your authenticator app.';
}

export function codeProblem(code: string, what: string): string | null {
  return code.trim() === '' ? `Enter ${what}.` : null;
}

// ---------------------------------------------------------------------------------------------------------------------
// The status page
// ---------------------------------------------------------------------------------------------------------------------

export function emailReasonText(reason: OwnerStatus['emailUnavailableReason']): string {
  if (reason === 'smtp_not_configured') return 'Sending mail is not set up on this server, so codes cannot be mailed to you. Use an offline recovery code instead.';
  if (reason === 'smtp_changed') return 'The mail settings were changed after you enrolled, so mailed codes are switched off until the owner confirms them again on the server. Use an offline recovery code meanwhile.';
  return 'Mailed codes cannot be sent right now. Use an offline recovery code instead.';
}

export type Tone = 'success' | 'warning' | 'danger';

export function recoveryCodesNote(remaining: number): { tone: Tone; text: string } {
  if (remaining <= 0) return { tone: 'danger', text: 'None left. If a mailed code cannot be sent you will not be able to authorise anything. Make new ones on the server now.' };
  if (remaining <= 2) return { tone: 'warning', text: `Only ${remaining} left. Make a new set on the server soon.` };
  return { tone: 'success', text: `${remaining} left.` };
}

export const SERVER_COMMANDS: ReadonlyArray<{ command: string; what: string }> = [
  { command: 'npm run owner:enroll', what: 'First-time setup: choose your security questions and your mailbox, and link your authenticator app unless the server has it switched off. Prints your offline recovery codes once.' },
  { command: 'npm run owner:status', what: 'Shows whether owner verification is set up, whether mailed codes work and how many recovery codes are left. Prints no secrets.' },
  { command: 'npm run owner:recover', what: 'Use when you lost your authenticator app or your recovery codes. Proves who you are again, then replaces them.' },
  { command: 'npm run owner:change-email', what: 'Changes the mailbox that receives the mailed codes.' },
];

export const OWNER_CANCELLED_CODE = 'OWNER_AUTHORISATION_CANCELLED';
export const OWNER_CANCELLED_TEXT = 'Owner authorisation was cancelled, so nothing was changed.';

/** "Rotate the signing key" reads as "rotate the signing key" after "You are about to"; an acronym ("DMS tenant") is left alone. */
export function phraseOf(label: string): string {
  const t = label.trim();
  return /^[A-Z][a-z]/.test(t) ? `${t[0]!.toLowerCase()}${t.slice(1)}` : t;
}
