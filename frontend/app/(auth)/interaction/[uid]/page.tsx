'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { BrandLogo } from '../../../../shared/components/BrandLogo';
import { getInteractionState, submitInteractionStep } from './actions';
import { apiPath } from '@shared/apiPath';
import toast from 'react-hot-toast';

/**
 * Real entry point for the OIDC login/consent flow — this is the exact URL
 * oidc-provider redirects the browser to (`interactions.url()` in
 * oidc/provider.ts returns `/interaction/${uid}`). Renders whichever step the
 * backend's interaction state machine says is current (login / totp /
 * change-password) by consuming its JSON "view-model" through the Server
 * Actions in ./actions.ts — the actual login/MFA/lockout/password-policy
 * logic all still lives in the backend's interactions/router.ts, unchanged
 * and unduplicated.
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

export default function InteractionPage() {
  const { uid } = useParams<{ uid: string }>();
  const [vm, setVm] = useState<ViewModel | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  useEffect(() => {
    getInteractionState(uid)
      .then((result) => {
        if (result.redirect) {
          window.location.href = result.redirect;
          return;
        }
        if (result.error || !result.view) {
          toast.error(result.error ?? 'This sign-in link is invalid or has expired.');
          return;
        }
        setVm({ view: result.view, locals: result.locals as ViewModel['locals'] });
        setEmail((result.locals as ViewModel['locals'])?.email ?? '');
      })
      .catch(() => toast.error('This sign-in link is invalid or has expired.'))
      .finally(() => setLoading(false));
  }, [uid]);

  async function submitStep(step: 'login' | 'totp' | 'password', fields: Record<string, string>) {
    if (!vm) return;
    setSubmitting(true);
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
        toast.error(result.error ?? 'Something went wrong. Please try again.');
        return;
      }
      setVm({ view: result.view, locals: result.locals as ViewModel['locals'] });
    } catch {
      toast.error('Something went wrong. Please try again.');
    } finally {
      setSubmitting(false);
    }
  }

  if (loading) return <BrandLogo />;
  if (!vm) {
    return (
      <>
        <BrandLogo />
        <div className="sso-error">
          This sign-in link is invalid or has expired. This is normal if it was reused (a bookmark, an old
          tab, or the browser&apos;s back button) — sign-in links are single-use.
        </div>
        <a href={apiPath('/portal/login')} className="sso-button" style={{ textDecoration: 'none', textAlign: 'center', display: 'block' }}>
          Start over
        </a>
      </>
    );
  }

  const { locals } = vm;

  if (vm.view === 'totp') {
    return (
      <>
        <BrandLogo />
        <h2 style={{ fontSize: '20px', margin: '0 0 4px' }}>Two-factor verification</h2>
        <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 22px' }}>
          Enter the current code from your authenticator app for <strong>{locals.clientName}</strong>.
        </p>
        {locals.error && <div className="sso-error">{locals.error}</div>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submitStep('totp', { code });
          }}
        >
          <label htmlFor="code" style={{ display: 'block', fontSize: '13px', fontWeight: 600, margin: '14px 0 6px' }}>
            Authentication code
          </label>
          <input
            id="code"
            className="sso-input"
            required
            autoFocus
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="123456"
          />
          <button type="submit" className="sso-button" disabled={submitting}>
            {submitting ? 'Verifying…' : 'Verify'}
          </button>
        </form>
      </>
    );
  }

  if (vm.view === 'change-password') {
    return (
      <>
        <BrandLogo />
        <h2 style={{ fontSize: '20px', margin: '0 0 4px' }}>Set a new password</h2>
        <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 22px' }}>
          An administrator reset your password — choose a new one to continue.
        </p>
        {locals.error && <div className="sso-error">{locals.error}</div>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            submitStep('password', { password: newPassword, confirm: confirmPassword });
          }}
        >
          <label htmlFor="new" style={{ display: 'block', fontSize: '13px', fontWeight: 600, margin: '14px 0 6px' }}>
            New password
          </label>
          <input
            id="new"
            type="password"
            className="sso-input"
            required
            minLength={8}
            autoFocus
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="At least 8 characters"
          />
          <label htmlFor="confirm" style={{ display: 'block', fontSize: '13px', fontWeight: 600, margin: '14px 0 6px' }}>
            Confirm new password
          </label>
          <input
            id="confirm"
            type="password"
            className="sso-input"
            required
            minLength={8}
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="Repeat the password above"
          />
          <button type="submit" className="sso-button" disabled={submitting}>
            {submitting ? 'Saving…' : 'Set password & continue'}
          </button>
        </form>
      </>
    );
  }

  // Default: login
  return (
    <>
      <BrandLogo />
      <h2 style={{ fontSize: '20px', margin: '0 0 4px' }}>Sign in</h2>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 22px' }}>
        Access <strong>{locals.clientName}</strong> with your Example Corp account.
      </p>
      {locals.error && <div className="sso-error">{locals.error}</div>}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          submitStep('login', { email, password });
        }}
        autoComplete="off"
      >
        <label htmlFor="email" style={{ display: 'block', fontSize: '13px', fontWeight: 600, margin: '14px 0 6px' }}>
          Email
        </label>
        <input
          id="email"
          name="email"
          type="email"
          className="sso-input"
          required
          autoFocus
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@examplecorp.com"
        />
        <label htmlFor="password" style={{ display: 'block', fontSize: '13px', fontWeight: 600, margin: '14px 0 6px' }}>
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          className="sso-input"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
        />
        <button type="submit" className="sso-button" disabled={submitting}>
          {submitting ? 'Signing in...' : 'Continue'}
        </button>
      </form>
      <div className="foot" style={{ marginTop: '20px', fontSize: '11px', color: 'var(--muted)', textAlign: 'center' }}>
        © Example Corp · Secured by OpenID Connect
      </div>
    </>
  );
}
