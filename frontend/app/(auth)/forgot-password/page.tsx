'use client';

import { useState } from 'react';
import { BrandLogo } from '../../../shared/components/BrandLogo';
import { useBranding } from '../../../shared/branding/BrandingProvider';
import { useHydrated } from '../../../shared/hooks/useHydrated';
import { apiPath } from '@shared/apiPath';

/**
 * "Forgot your password?" There is no mail server, so nothing is emailed: the request goes to the administrators (Admin > Users), who reset
 * the password and tell the person in person or by phone. The server's answer is the same for every address, so this page never says
 * whether an account exists, and neither does it.
 */
export default function ForgotPasswordPage() {
  const { passwordResetRequests, supportContact, footerText } = useBranding();
  const hydrated = useHydrated();
  const [email, setEmail] = useState('');
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [answer, setAnswer] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const res = await fetch(apiPath('/api/v1/auth/password-reset-request'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, note }),
      });
      const json = (await res.json().catch(() => ({}))) as { data?: { message?: string }; error?: { message?: string } };
      if (res.status === 429) {
        setError('Too many requests from this address. Please wait a few minutes, or contact the help desk.');
      } else if (!res.ok || !json.data?.message) {
        setError(json.error?.message ?? 'The request could not be sent. Try again, or contact the help desk.');
      } else {
        setAnswer(json.data.message);
      }
    } catch {
      setError('Could not reach the server. Check your connection and try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <BrandLogo />
      <h2 className="sso-step-title">Forgot your password?</h2>
      {!passwordResetRequests ? (
        <>
          <p className="sub">Password reset requests are switched off. {supportContact ? `Please contact: ${supportContact}.` : 'Please contact the help desk.'}</p>
          <p className="sso-help">
            <button type="button" className="sso-link-button" onClick={() => window.history.back()}>Back to sign in</button>
          </p>
        </>
      ) : answer ? (
        <>
          <div className="sso-notice" role="status">{answer}</div>
          <p className="sso-help">
            <button type="button" className="sso-link-button" onClick={() => window.history.back()}>Back to sign in</button>
          </p>
        </>
      ) : (
        <>
          <p className="sub">
            Tell us who you are and an administrator will reset your password and contact you. Nothing is sent by email.
            {supportContact ? ` Need it sooner? ${supportContact}.` : ''}
          </p>
          {error ? <div className="sso-error" role="alert">{error}</div> : null}
          <form
            method="post"
            data-hydrated={hydrated}
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <label htmlFor="email" className="sso-label">Email</label>
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
            <label htmlFor="note" className="sso-label">How can we recognise you? (optional)</label>
            <input
              id="note"
              name="note"
              type="text"
              className="sso-input"
              maxLength={200}
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Your name, department, a phone number to reach you"
            />
            <button type="submit" className="sso-button" disabled={busy}>
              {busy ? 'Sending…' : 'Ask for a reset'}
            </button>
          </form>
          <p className="sso-help">
            <button type="button" className="sso-link-button" onClick={() => window.history.back()}>Back to sign in</button>
          </p>
        </>
      )}
      {footerText ? <div className="foot">{footerText}</div> : null}
    </>
  );
}
