'use client';

import { useCallback, useEffect, useId, useReducer, useRef, useState } from 'react';
import { Modal } from '../ui/Modal';
import {
  answersProblem,
  codeProblem,
  currentStep,
  flowReducer,
  formatCountdown,
  formatWait,
  initialFlowState,
  introSteps,
  phraseOf,
  progressOf,
  secondsUntil,
  stepLabel,
  totpProblem,
  type StartData,
  type Step,
  type Ticket,
} from './ownerLogic';
import { OwnerCallError, fetchOwnerCsrf, isCsrfProblem, ownerGet, ownerPost, toFailure } from './ownerClient';
import { useNow } from './useNow';

export interface OwnerDialogProps {
  /** The operation key the server named (`error.operation`, or one from the status list). */
  operation: string;
  /** Passed back to the server unchanged, so the authorisation is bound to it. */
  target: string | null;
  /** The server's plain-language name and warning for the operation. */
  label: string;
  warning: string;
  /** Shown before the steps, e.g. "The last authorisation was not accepted". */
  notice?: string;
  /** The server already said the owner has not enrolled: explain, do not loop. */
  notEnrolled?: boolean;
  /** Ask for the target before starting (an action in another system names what it is for). */
  needsTarget?: boolean;
  /** Called once with the authorisation. The dialog does nothing after this; the caller closes it. */
  onTicket: (ticket: Ticket) => void;
  /** Called when the owner closes the dialog without finishing. `notEnrolled` is true when the reason was that nobody has enrolled. */
  onCancel: (notEnrolled: boolean) => void;
}

const NO_AUTOFILL = { autoComplete: 'off', 'data-1p-ignore': true, 'data-lpignore': 'true', 'data-form-type': 'other', autoCapitalize: 'off', spellCheck: false } as const;

/**
 * The owner's verification dialog: security questions, then a mailed code (or an offline recovery code), then the authenticator app
 * code (only when the owner's enrolment uses one: the steps the server lists are the steps shown). What is typed is read from the form when it is sent and the form is cleared at once: no answer or code is kept in state,
 * logged, or shown again.
 */
export function OwnerVerificationDialog(props: OwnerDialogProps) {
  const { operation, target, label, warning, notice, needsTarget = false } = props;
  const [state, dispatch] = useReducer(flowReducer, props.notEnrolled === true, initialFlowState);
  const [typedTarget, setTypedTarget] = useState(target ?? '');
  const [localProblem, setLocalProblem] = useState<string | null>(null);
  /** Whether the owner's enrolment uses the authenticator app: learnt from the server so the first screen never promises a step that will not come. */
  const [authenticator, setAuthenticator] = useState<boolean | null>(null);
  const baseId = useId();
  const bodyRef = useRef<HTMLDivElement>(null);
  const csrfRef = useRef<string | null>(null);
  const cancelledRef = useRef(false);
  const stateRef = useRef(state);
  const propsRef = useRef(props);
  useEffect(() => {
    stateRef.current = state;
    propsRef.current = props;
  });

  const step = currentStep(state.steps);
  const now = useNow(state.phase === 'locked');

  // Escape, the backdrop and the Cancel button all come here. Stable on purpose: Modal re-focuses whenever its onClose changes.
  const cancel = useCallback(() => {
    cancelledRef.current = true;
    propsRef.current.onCancel(stateRef.current.phase === 'not-enrolled');
  }, []);

  useEffect(() => {
    if (props.notEnrolled === true) return undefined;
    let live = true;
    ownerGet<{ authenticator?: boolean | null }>('/status')
      .then((s) => {
        if (live && typeof s.authenticator === 'boolean') setAuthenticator(s.authenticator);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [props.notEnrolled]);

  // Put the cursor in the field that needs it whenever the step, the phase or an error changes.
  useEffect(() => {
    bodyRef.current?.querySelector<HTMLElement>('[data-owner-focus]')?.focus();
  }, [state.phase, step, state.emailSent, state.recoveryOffered, state.error, localProblem]);

  /** A POST with the CSRF token; one fresh token and one more try if the server says the token did not match. */
  async function post<T>(path: string, body: Record<string, unknown>): Promise<T> {
    csrfRef.current ??= await fetchOwnerCsrf();
    try {
      return await ownerPost<T>(path, { ...body, csrf: csrfRef.current });
    } catch (err) {
      if (!isCsrfProblem(err)) throw err;
      csrfRef.current = await fetchOwnerCsrf();
      return ownerPost<T>(path, { ...body, csrf: csrfRef.current });
    }
  }

  /** Runs one server call, turning any failure into the dialog's state. Returns undefined on failure (or when the owner has cancelled meanwhile). */
  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setLocalProblem(null);
    dispatch({ type: 'busy' });
    try {
      const out = await fn();
      return cancelledRef.current ? undefined : out;
    } catch (err) {
      if (!cancelledRef.current) dispatch({ type: 'failure', failure: toFailure(err), now: Date.now() });
      return undefined;
    }
  }

  async function start() {
    if (needsTarget && typedTarget.trim() === '') {
      setLocalProblem('Say what this authorisation is for.');
      return;
    }
    dispatch({ type: 'begin' });
    setLocalProblem(null);
    try {
      csrfRef.current = await fetchOwnerCsrf();
      const data = await ownerPost<StartData>('/start', { operation, target: needsTarget ? typedTarget.trim() : target, csrf: csrfRef.current });
      if (!cancelledRef.current) dispatch({ type: 'started', data });
    } catch (err) {
      if (!cancelledRef.current) dispatch({ type: 'failure', failure: toFailure(err), now: Date.now() });
    }
  }

  async function afterStep(steps: Step[]) {
    dispatch({ type: 'steps', steps });
    if (currentStep(steps) === null) await finish();
  }

  async function finish() {
    const challengeId = stateRef.current.challengeId;
    if (!challengeId) return;
    dispatch({ type: 'finishing' });
    try {
      const ticket = await post<Ticket>('/finish', { challengeId });
      if (cancelledRef.current) return;
      dispatch({ type: 'finished', ticket });
      propsRef.current.onTicket(ticket);
    } catch (err) {
      if (!cancelledRef.current) dispatch({ type: 'failure', failure: toFailure(err), now: Date.now() });
    }
  }

  async function submitQuestions(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = e.currentTarget;
    const data = new FormData(form);
    const answers = state.questions.map((_, i) => String(data.get(`a${i}`) ?? ''));
    const problem = answersProblem(answers);
    if (problem) {
      setLocalProblem(problem);
      return;
    }
    form.reset();
    const out = await run(() => post<{ steps: Step[] }>('/answer-questions', { challengeId: state.challengeId, answers }));
    if (out) await afterStep(out.steps);
  }

  async function sendEmail() {
    const out = await run(() => post<{ maskedAddress: string; expiresInSeconds: number }>('/send-email-code', { challengeId: state.challengeId }));
    if (out) dispatch({ type: 'email-sent', maskedAddress: out.maskedAddress, expiresInSeconds: out.expiresInSeconds });
  }

  async function submitCode(e: React.FormEvent<HTMLFormElement>, kind: 'email' | 'recovery' | 'totp') {
    e.preventDefault();
    const form = e.currentTarget;
    const code = String(new FormData(form).get('code') ?? '').trim();
    const problem = kind === 'totp' ? totpProblem(code) : codeProblem(code, kind === 'email' ? 'the code we sent you' : 'one of your recovery codes');
    if (problem) {
      setLocalProblem(problem);
      return;
    }
    form.reset();
    const path = kind === 'email' ? '/verify-email-code' : kind === 'recovery' ? '/verify-recovery-code' : '/verify-totp';
    const out = await run(() => post<{ steps: Step[] }>(path, { challengeId: state.challengeId, code }));
    if (out) await afterStep(out.steps);
  }

  // -- pieces ---------------------------------------------------------------------------------------------------------

  const busy = state.busy;
  const errorText = localProblem ?? state.error;

  const cancelButton = (
    <button type="button" className="admin-btn secondary" onClick={cancel}>
      Cancel
    </button>
  );

  const progress = progressOf(state.steps);
  const progressList =
    state.steps.length > 0 ? (
      <div className="owner-progress">
        <p className="owner-progress-label">{progress.label}</p>
        <ol aria-label="Steps">
          {state.steps.map((s) => (
            <li key={s.id} className={s.done ? 'done' : s.id === step ? 'current' : ''} aria-current={s.id === step ? 'step' : undefined}>
              <span className="owner-progress-mark" aria-hidden="true">{s.done ? '✓' : state.steps.indexOf(s) + 1}</span>
              <span>
                {stepLabel(s.id, state.recoveryOffered)}
                <span className="admin-visually-hidden">{s.done ? ' (done)' : s.id === step ? ' (now)' : ' (later)'}</span>
              </span>
            </li>
          ))}
        </ol>
      </div>
    ) : null;

  function activeStep() {
    if (step === 'questions') {
      return (
        <form key="questions" className="owner-form" onSubmit={(e) => void submitQuestions(e)} noValidate>
          <p className="owner-step-help">Answer your three security questions. Type each answer the way you set it up.</p>
          {state.questions.map((q, i) => (
            <div className="ui-field" key={q.index}>
              <label className="sub" htmlFor={`${baseId}-q${i}`}>{q.prompt}</label>
              <input id={`${baseId}-q${i}`} name={`a${i}`} type="password" className="ui-input" disabled={busy} data-owner-focus={i === 0 ? true : undefined} {...NO_AUTOFILL} />
            </div>
          ))}
          <div className="owner-actions">
            {cancelButton}
            <button type="submit" className="admin-btn" disabled={busy}>{busy ? 'Checking…' : 'Check my answers'}</button>
          </div>
        </form>
      );
    }
    if (step === 'email') {
      if (state.recoveryOffered) {
        return (
          <form key="recovery" className="owner-form" onSubmit={(e) => void submitCode(e, 'recovery')} noValidate>
            <p className="owner-step-help">
              {state.emailAvailable ? 'The emailed code could not be sent. ' : 'Mailed codes are not available right now. '}
              Use one of the offline recovery codes you were given when you set up owner verification. Each one works only once.
            </p>
            {state.recoveryCodeAvailable === false ? (
              <p className="owner-notice" role="note">No recovery codes are left. The server operator must make new ones with the recovery tool (see the Owner verification page). Cancel for now.</p>
            ) : null}
            <div className="ui-field">
              <label className="sub" htmlFor={`${baseId}-recovery`}>Offline recovery code</label>
              <input id={`${baseId}-recovery`} name="code" type="password" className="ui-input" disabled={busy} data-owner-focus {...NO_AUTOFILL} />
            </div>
            <div className="owner-actions">
              {cancelButton}
              <button type="submit" className="admin-btn" disabled={busy}>{busy ? 'Checking…' : 'Check recovery code'}</button>
            </div>
          </form>
        );
      }
      if (!state.emailSent) {
        return (
          <div key="email-send" className="owner-form">
            <p className="owner-step-help">We will send a code to the mailbox you registered when you set up owner verification.</p>
            <div className="owner-actions">
              {cancelButton}
              <button type="button" className="admin-btn" disabled={busy} data-owner-focus onClick={() => void sendEmail()}>
                {busy ? 'Sending…' : 'Send the code to my mailbox'}
              </button>
            </div>
          </div>
        );
      }
      return (
        <form key="email-code" className="owner-form" onSubmit={(e) => void submitCode(e, 'email')} noValidate>
          <p className="owner-step-help" role="status">
            A code was sent to <strong>{state.emailSent.maskedAddress}</strong>. It stays valid for {formatWait(state.emailSent.expiresInSeconds)}.
          </p>
          <div className="ui-field">
            <label className="sub" htmlFor={`${baseId}-email`}>The code from your mailbox</label>
            <input id={`${baseId}-email`} name="code" type="password" className="ui-input" disabled={busy} inputMode="numeric" data-owner-focus {...NO_AUTOFILL} />
          </div>
          <div className="owner-actions">
            {cancelButton}
            <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => void sendEmail()}>Send a new code</button>
            <button type="submit" className="admin-btn" disabled={busy}>{busy ? 'Checking…' : 'Check code'}</button>
          </div>
        </form>
      );
    }
    if (step === 'totp') {
      return (
        <form key="totp" className="owner-form" onSubmit={(e) => void submitCode(e, 'totp')} noValidate>
          <p className="owner-step-help">Open your authenticator app and type the 6 digits it shows for this account.</p>
          <div className="ui-field">
            <label className="sub" htmlFor={`${baseId}-totp`}>Authenticator app code</label>
            <input id={`${baseId}-totp`} name="code" type="text" inputMode="numeric" pattern="[0-9]*" maxLength={6} className="ui-input owner-code" disabled={busy} data-owner-focus {...NO_AUTOFILL} />
          </div>
          <div className="owner-actions">
            {cancelButton}
            <button type="submit" className="admin-btn" disabled={busy}>{busy ? 'Authorising…' : 'Authorise'}</button>
          </div>
        </form>
      );
    }
    // Every step is done but the authorisation was not issued (the last call failed): offer it again.
    return (
      <div key="all-done" className="owner-form">
        <p className="owner-step-help">All steps are done.</p>
        <div className="owner-actions">
          {cancelButton}
          <button type="button" className="admin-btn" disabled={busy} data-owner-focus onClick={() => void finish()}>Authorise</button>
        </div>
      </div>
    );
  }

  function body() {
    switch (state.phase) {
      case 'intro':
        return (
          <div className="owner-form">
            <p className="owner-action">You are about to <strong>{phraseOf(label)}</strong>.</p>
            {warning ? <p className="owner-warning" role="note">{warning}</p> : null}
            <p>This needs your owner authorisation. {introSteps(authenticator)}</p>
            {notice ? <p className="owner-notice" role="status">{notice}</p> : null}
            {needsTarget ? (
              <div className="ui-field">
                <label className="sub" htmlFor={`${baseId}-target`}>What is this authorisation for?</label>
                <input id={`${baseId}-target`} className="ui-input" value={typedTarget} maxLength={200} autoComplete="off" onChange={(e) => { setTypedTarget(e.target.value); setLocalProblem(null); }} />
                <p className="ui-field-hint">Type it exactly as the other system will ask for it. The authorisation works for this and nothing else.</p>
              </div>
            ) : null}
            <div className="owner-actions">
              {cancelButton}
              <button type="button" className="admin-btn" data-autofocus data-owner-focus onClick={() => void start()}>Continue</button>
            </div>
          </div>
        );
      case 'starting':
        return <p role="status" aria-busy="true">Getting ready…</p>;
      case 'steps':
        return (
          <>
            {progressList}
            {activeStep()}
          </>
        );
      case 'finishing':
        return <><p role="status" aria-busy="true">Authorising…</p>{progressList}</>;
      case 'done':
        return <p role="status">Authorised.</p>;
      case 'locked': {
        const remaining = now === null || state.lockedUntil === null ? null : secondsUntil(state.lockedUntil, now);
        return (
          <div className="owner-form">
            <p className="owner-notice" role="note">
              {remaining !== null && remaining > 0 ? `Too many wrong answers. Owner verification is locked. You can try again in ${formatCountdown(remaining)}.` : state.error}
            </p>
            <p>Nothing was changed. Wait for the lock to end, then start again.</p>
            <div className="owner-actions">
              {cancelButton}
              <button type="button" className="admin-btn" disabled={remaining === null || remaining > 0} onClick={() => dispatch({ type: 'restart' })}>Start again</button>
            </div>
          </div>
        );
      }
      case 'expired':
      case 'failed':
        return (
          <div className="owner-form">
            <p>{state.phase === 'expired' ? 'Nothing was changed.' : 'The check could not be started. Nothing was changed.'}</p>
            <div className="owner-actions">
              {cancelButton}
              <button type="button" className="admin-btn" data-owner-focus onClick={() => dispatch({ type: 'restart' })}>Start again</button>
            </div>
          </div>
        );
      case 'not-enrolled':
        return (
          <div className="owner-form">
            <p>
              Owner verification has not been set up yet, so this action cannot be authorised. The server operator must run <code className="admin-code">npm run owner:enroll</code> on
              the server (the Owner verification page and the SSO operations guide explain how). Nothing was changed.
            </p>
            <div className="owner-actions">
              <button type="button" className="admin-btn" data-autofocus data-owner-focus onClick={cancel}>Close</button>
            </div>
          </div>
        );
      default:
        return null;
    }
  }

  const showError = errorText && state.phase !== 'not-enrolled' && state.phase !== 'locked';

  return (
    <Modal open title="Owner authorisation" onClose={cancel} width={520}>
      <div ref={bodyRef} className="owner-dialog">
        {body()}
        <div className="owner-live" aria-live="assertive" aria-atomic="true">
          {showError ? <p className="ui-field-error owner-error">{errorText}</p> : null}
        </div>
      </div>
    </Modal>
  );
}

export { OwnerCallError };
