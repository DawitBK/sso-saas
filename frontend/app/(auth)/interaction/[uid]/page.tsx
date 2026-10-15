'use client';

import { useEffect, useRef, useState } from 'react';
import { useParams } from 'next/navigation';
import { BrandLogo } from '../../../../shared/components/BrandLogo';
import { useBranding } from '../../../../shared/branding/BrandingProvider';
import { PasswordInput } from '../../../../shared/ui/PasswordInput';
import { Skeleton } from '../../../../shared/ui/States';
import { useHydrated } from '../../../../shared/hooks/useHydrated';
import { getInteractionState, submitInteractionStep } from './actions';
import { apiPath } from '@shared/apiPath';

/**
 * Real entry point for the OIDC login/consent flow — this is the exact URL
 * oidc-provider redirects the browser to (`interactions.url()` in
 * oidc/provider.ts returns `/interaction/${uid}`). Renders whichever step the
 * backend's interaction state machine says is current (login / totp /
 * change-password) by consuming its JSON "view-model" through the Server
 * Actions in ./actions.ts — the actual login/MFA/lockout/password-policy
 * logic all still lives in the backend's interactions/router.ts, unchanged
 * and unduplicated.
 *
 * What this page adds on top of that: the branding (name, notice, help contact, footer), a show/hide password control and Caps
 * Lock warning, autocomplete attributes a password manager understands (the form used to switch autofill off, which pushes
 * people toward weaker, memorised passwords), the real password rule on the new-password step, and errors that are announced to
 * screen readers and focus-managed instead of only flashing as a toast.
 */

interface ViewModel {
  view: 'login' | 'totp' | 'change-password' | string;
  locals: {
    uid: string;
    clientName: string;
    csrf: string;
    error: string | null;
    email?: string;
  };
}

function FormError({ message }: { message: string | null }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (message) ref.current?.focus();
  }, [message]);
  if (!message) return null;
  return (
    <div ref={ref} className="sso-error" role="alert" tabIndex={-1}>
      {message}
    </div>
  );
}

function Help() {
  const { supportContact, passwordResetRequests } = useBranding();
  return (
    <>
      {passwordResetRequests ? (
        <p className="sso-help">
          <a href={apiPath('/forgot-password')}>Forgot your password?</a>
        </p>
      ) : null}
      {supportContact ? <p className="sso-help">Need help signing in? {supportContact}</p> : null}
    </>
  );
}

function Foot() {
  const { footerText } = useBranding();
  return footerText ? <div className="foot">{footerText}</div> : null;
}

function Notice() {
  const { loginNotice } = useBranding();
  if (!loginNotice) return null;
  return (
    <div className="sso-notice" role="note">
      {loginNotice}
    </div>
  );
}

export default function InteractionPage() {
  const { uid } = useParams<{ uid: string }>();
  const { passwordMinLength } = useBranding();
  const hydrated = useHydrated();
  const [vm, setVm] = useState<ViewModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  // Errors from the server (wrong password...) arrive inside the next view-model; failures to even reach it are kept here.
  const [problem, setProblem] = useState<string | null>(null);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  // The authenticator step can take a recovery code instead (a lost phone).
  const [useRecovery, setUseRecovery] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  useEffect(() => {
    // React runs this effect twice in development (StrictMode). Without the flag the first call's answer arrived after the
    // person had started typing and wiped what they had entered; the cleanup makes only the live call count.
    let current = true;
    getInteractionState(uid)
      .then((result) => {
        if (!current) return;
        if (result.redirect) {
          window.location.href = result.redirect;
          return;
        }
        if (result.error || !result.view) return;
        setVm({ view: result.view, locals: result.locals as ViewModel['locals'] });
        // Prefill (a retried sign-in keeps the address) but never over what is already typed.
        setEmail((typed) => typed || ((result.locals as ViewModel['locals'])?.email ?? ''));
      })
      .catch(() => undefined)
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [uid]);

  async function submitStep(step: 'login' | 'totp' | 'password', fields: Record<string, string>) {
    if (!vm) return;
    setSubmitting(true);
    setProblem(null);
    try {
      const result = await submitInteractionStep(uid, step, { csrf: vm.locals.csrf, ...fields });
      if (result.redirect) {
        // Real browser navigation — required to actually complete the OIDC
        // flow (consent auto-grant, then the RP's callback), not something a
        // client-side call can substitute for.
        window.location.href = result.redirect;
        return;
      }
      if (result.error || !result.view) {
        setProblem(result.error ?? 'Something went wrong. Please try again.');
        return;
      }
      setVm({ view: result.view, locals: result.locals as ViewModel['locals'] });
      // A wrong password must not leave the old one sitting in the field.
      if (step === 'login') setPassword('');
      if (step === 'totp') setCode('');
    } catch {
      setProblem('Could not reach the sign-in service. Check your connection and try again.');
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) {
    return (
      <div role="status" aria-live="polite" aria-busy="true">
        <BrandLogo />
        <span className="admin-visually-hidden">Loading the sign-in form…</span>
        <div style={{ display: 'grid', gap: 12, marginTop: 24 }}>
          <Skeleton width={120} height={22} />
          <Skeleton height={40} />
          <Skeleton height={40} />
          <Skeleton height={44} />
        </div>
      </div>
    );
  }
  if (!vm) {
    return (
      <>
        <BrandLogo />
        <div className="sso-error" role="alert">
          This sign-in link is invalid or has expired. This is normal if it was reused (a bookmark, an old
          tab, or the browser&apos;s back button) — sign-in links are single-use.
        </div>
        <a href={apiPath('/portal/login')} className="sso-button" style={{ textDecoration: 'none', textAlign: 'center', display: 'block' }}>
          Start over
        </a>
        <Help />
        <Foot />
      </>
    );
  }

  const { locals } = vm;
  const error = problem ?? locals.error;

  if (vm.view === 'totp') {
    return (
      <>
        <BrandLogo />
        <h2 className="sso-step-title">Two-factor verification</h2>
        <p className="sub">
          {useRecovery ? (
            <>Enter one of your recovery codes to sign in to <strong>{locals.clientName}</strong>. Each works once.</>
          ) : (
            <>Enter the current code from your authenticator app for <strong>{locals.clientName}</strong>.</>
          )}
        </p>
        <FormError message={error} />
        <form
          method="post"
          data-hydrated={hydrated}
          onSubmit={(e) => {
            e.preventDefault();
            submitStep('totp', { code });
          }}
        >
          <label htmlFor="code" className="sso-label">
            {useRecovery ? 'Recovery code' : 'Authentication code'}
          </label>
          <input
            id="code"
            name="code"
            className="sso-input sso-input-code"
            required
            autoFocus
            key={useRecovery ? 'recovery' : 'totp'}
            inputMode={useRecovery ? 'text' : 'numeric'}
            pattern={useRecovery ? undefined : '[0-9 ]*'}
            maxLength={useRecovery ? 16 : 9}
            autoComplete="one-time-code"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={useRecovery ? 'abcde-fghjk' : '123456'}
          />
          <button type="submit" className="sso-button" disabled={submitting}>
            {submitting ? 'Verifying…' : 'Verify'}
          </button>
        </form>
        <p className="sso-help">
          <button type="button" className="sso-link-button" onClick={() => { setUseRecovery((v) => !v); setCode(''); setProblem(null); }}>
            {useRecovery ? 'Use my authenticator app instead' : 'Lost your phone? Use a recovery code'}
          </button>
        </p>
        <p className="sso-help">No recovery codes either? An administrator can reset two-factor sign-in for your account.</p>
        <Help />
        <Foot />
      </>
    );
  }

  if (vm.view === 'change-password') {
    const tooShort = newPassword.length > 0 && newPassword.length < passwordMinLength;
    const mismatch = confirmPassword.length > 0 && confirmPassword !== newPassword;
    return (
      <>
        <BrandLogo />
        <h2 className="sso-step-title">Set a new password</h2>
        <p className="sub">An administrator reset your password — choose a new one to continue.</p>
        <FormError message={error} />
        <form
          method="post"
          data-hydrated={hydrated}
          onSubmit={(e) => {
            e.preventDefault();
            if (mismatch || tooShort) return;
            submitStep('password', { password: newPassword, confirm: confirmPassword });
          }}
        >
          <label htmlFor="new" className="sso-label">
            New password
          </label>
          <PasswordInput
            id="new"
            autoComplete="new-password"
            minLength={passwordMinLength}
            autoFocus
            value={newPassword}
            onChange={setNewPassword}
            placeholder={`At least ${passwordMinLength} characters`}
            describedBy="pw-rules"
          />
          <ul id="pw-rules" className="sso-rules" aria-live="polite">
            <li className={newPassword.length >= passwordMinLength ? 'met' : ''}>At least {passwordMinLength} characters</li>
            <li className={confirmPassword.length > 0 && !mismatch ? 'met' : ''}>Both entries match</li>
          </ul>
          <label htmlFor="confirm" className="sso-label">
            Confirm new password
          </label>
          <PasswordInput id="confirm" autoComplete="new-password" minLength={passwordMinLength} value={confirmPassword} onChange={setConfirmPassword} placeholder="Repeat the password above" />
          <button type="submit" className="sso-button" disabled={submitting || tooShort || mismatch}>
            {submitting ? 'Saving…' : 'Set password & continue'}
          </button>
        </form>
        <Help />
        <Foot />
      </>
    );
  }

  // Default: login
  return (
    <>
      <BrandLogo />
      <Notice />
      <h2 className="sso-step-title">Sign in</h2>
      <p className="sub">
        Access <strong>{locals.clientName}</strong> with your Example Corp account.
      </p>
      <FormError message={error} />
      <form
        method="post"
        data-hydrated={hydrated}
        onSubmit={(e) => {
          e.preventDefault();
          submitStep('login', { email, password });
        }}
      >
        <label htmlFor="email" className="sso-label">
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          className="sso-input"
          required
          autoFocus
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@examplecorp.com"
        />
        <label htmlFor="password" className="sso-label">
          Password
        </label>
        <PasswordInput id="password" autoComplete="current-password" value={password} onChange={setPassword} placeholder="Your password" />
        <button type="submit" className="sso-button" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Continue'}
        </button>
      </form>
      <Help />
      <Foot />
    </>
  );
}
