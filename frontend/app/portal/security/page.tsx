'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { AlertTriangle, ShieldCheck } from 'lucide-react';
import { useBranding } from '../../../shared/branding/BrandingProvider';
import { formatDateTime } from '../../../shared/lib/format';
import { isNotableSuccess, loginReasonLabel } from '../../../shared/lib/loginReasons';
import { PasswordInput } from '../../../shared/ui/PasswordInput';
import { QrCode } from '../../../shared/ui/QrCode';
import { RecoveryCodes } from '../../../shared/ui/RecoveryCodes';
import { Skeleton } from '../../../shared/ui/States';
import {
  getSecurityState,
  totpStart,
  totpConfirm,
  totpDisable,
  regenerateRecoveryCodes,
  changePassword,
  killSession,
  type SecurityViewModel,
} from './actions';

const SESSION_LABEL: Record<string, string> = { portal: 'Portal and console', sso: 'Single sign-on (applications)', gateway: 'GMS gateway' };

export default function SecurityPage() {
  const { passwordMinLength } = useBranding();
  const [loading, setLoading] = useState(true);
  const [locals, setLocals] = useState<SecurityViewModel['locals'] | null>(null);
  const [busy, setBusy] = useState(false);
  // The recovery codes arrive in exactly one response; they are held here until the person confirms they have saved them.
  const [codesToShow, setCodesToShow] = useState<string[] | null>(null);

  const [totpCode, setTotpCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [regenCode, setRegenCode] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const apply = useCallback((vm: SecurityViewModel) => {
    if (vm.redirect) {
      window.location.href = vm.redirect;
      return;
    }
    if (vm.error || !vm.locals) {
      toast.error(vm.error ?? 'Could not load security settings.');
      setLoading(false);
      return;
    }
    setLocals(vm.locals);
    if (vm.locals.newRecoveryCodes?.length) setCodesToShow(vm.locals.newRecoveryCodes);
    if (vm.locals.error) toast.error(vm.locals.error);
    if (vm.locals.passwordError) toast.error(vm.locals.passwordError);
    setLoading(false);
  }, []);

  // The mount fetch. It deliberately does not raise `loading` first: the state already starts `true`, and
  // react-hooks/set-state-in-effect forbids a synchronous setState in an effect body.
  useEffect(() => {
    // React runs this twice in development; only the live call may apply its answer (each answer carries a CSRF token).
    let current = true;
    getSecurityState()
      .then((vm) => { if (current) apply(vm); })
      .catch(() => {
        if (!current) return;
        toast.error('Could not load security settings.');
        setLoading(false);
      });
    return () => { current = false; };
  }, [apply]);

  async function run(action: () => Promise<SecurityViewModel>, after?: (vm: SecurityViewModel) => void) {
    setBusy(true);
    try {
      const vm = await action();
      apply(vm);
      after?.(vm);
    } catch {
      toast.error('Something went wrong. Please try again.');
    } finally {
      setBusy(false);
    }
  }

  if (loading) {
    return (
      <div role="status" aria-busy="true" style={{ display: 'grid', gap: 12 }}>
        <Skeleton width={140} height={24} />
        <Skeleton height={90} />
        <Skeleton height={140} />
      </div>
    );
  }
  if (!locals) return <div className="sso-error" role="alert">Could not load security settings.</div>;

  if (codesToShow) {
    return (
      <>
        <h2 style={{ margin: '0 0 12px' }}>Security</h2>
        <RecoveryCodes codes={codesToShow} email={locals.userEmail} onDone={() => setCodesToShow(null)} />
      </>
    );
  }

  const lowCodes = locals.mfaEnabled && locals.recoveryCodesRemaining <= 2;

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
        <div>
          <h2 style={{ marginBottom: '2px' }}>Security</h2>
          <p className="sub" style={{ margin: 0 }}>{locals.userEmail}</p>
        </div>
        <Link href="/portal" className="admin-link" style={{ fontSize: '12px' }}>← Back to apps</Link>
      </div>

      <h3 className="admin-section-title">Two-factor sign-in</h3>
      {locals.pending ? (
        <>
          <p className="sub" style={{ marginTop: 0 }}>
            <strong>1.</strong> Scan this with your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password…).
          </p>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
            <QrCode text={locals.pending.uri} label="QR code to add this account to your authenticator app" />
            <div style={{ flex: 1, minWidth: 200 }}>
              <p className="sub" style={{ margin: '0 0 6px', fontSize: 12 }}>Cannot scan? Choose “Enter a setup key” and type:</p>
              <code className="admin-code" style={{ display: 'block', fontSize: 14, letterSpacing: '.1em', padding: '8px 10px', wordBreak: 'break-all', userSelect: 'all' }}>{locals.pending.secret}</code>
            </div>
          </div>
          <p className="sub"><strong>2.</strong> Enter the 6-digit code the app shows, to finish:</p>
          <form
            method="post"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() => totpConfirm(locals.csrf, totpCode), () => setTotpCode(''));
            }}
          >
            <label htmlFor="enroll-code" className="admin-visually-hidden">6-digit code</label>
            <input id="enroll-code" className="sso-input sso-input-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} required autoFocus placeholder="000000" value={totpCode} onChange={(e) => setTotpCode(e.target.value)} />
            <button className="sso-button" type="submit" disabled={busy}>Turn on two-factor sign-in</button>
          </form>
        </>
      ) : locals.mfaEnabled ? (
        <>
          <p className="sub" style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={18} color="var(--success)" aria-hidden="true" />
            <span>Two-factor sign-in is <strong style={{ color: 'var(--success-text)' }}>on</strong>: every sign-in asks for a code from your app.</span>
          </p>

          <div className="sso-subcard">
            <strong>Recovery codes</strong>
            <p className="sub" style={{ margin: '4px 0 8px' }}>
              {locals.recoveryCodesRemaining === 0
                ? 'You have none left. Create a new set so you can get back in if you lose your phone.'
                : `${locals.recoveryCodesRemaining} unused. Each works once if you lose your phone.`}
            </p>
            {lowCodes ? (
              <p role="status" style={{ color: 'var(--warning-text)', fontSize: 12, display: 'flex', gap: 6, alignItems: 'center', margin: '0 0 8px' }}>
                <AlertTriangle size={14} aria-hidden="true" /> Running low. Creating a new set replaces the old one.
              </p>
            ) : null}
            <form
              method="post"
              onSubmit={(e) => {
                e.preventDefault();
                void run(() => regenerateRecoveryCodes(locals.csrf, regenCode), () => setRegenCode(''));
              }}
            >
              <label htmlFor="regen-code" className="sub" style={{ display: 'block', margin: '0 0 4px', fontSize: 12 }}>Confirm with a current code from your app to create a new set</label>
              <input id="regen-code" className="sso-input sso-input-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} required placeholder="000000" value={regenCode} onChange={(e) => setRegenCode(e.target.value)} />
              <button className="sso-button secondary" type="submit" disabled={busy}>Create new recovery codes</button>
            </form>
          </div>

          <p className="sub" style={{ marginTop: 16 }}>To turn two-factor off, confirm with a current code:</p>
          <form
            method="post"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() => totpDisable(locals.csrf, disableCode), () => setDisableCode(''));
            }}
          >
            <label htmlFor="disable-code" className="admin-visually-hidden">Current 6-digit code</label>
            <input id="disable-code" className="sso-input sso-input-code" type="text" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9 ]*" maxLength={7} required placeholder="000000" value={disableCode} onChange={(e) => setDisableCode(e.target.value)} />
            <button className="sso-button danger" type="submit" disabled={busy}>Turn off two-factor sign-in</button>
          </form>
          <p className="sub" style={{ fontSize: '11px', marginTop: '10px' }}>
            Lost your phone and your recovery codes? An administrator can reset two-factor sign-in for your account.
          </p>
        </>
      ) : (
        <>
          <p className="sub" style={{ marginTop: 0 }}>
            Two-factor sign-in is <strong>off</strong>. With it on, signing in needs your password <em>and</em> a 6-digit code from an authenticator app, so a stolen password alone is not enough.
          </p>
          <form method="post" onSubmit={(e) => { e.preventDefault(); void run(() => totpStart(locals.csrf)); }}>
            <button className="sso-button" type="submit" disabled={busy}>Set up two-factor sign-in</button>
          </form>
        </>
      )}

      <h3 className="admin-section-title">Password</h3>
      {locals.canChangePassword ? (
        <form
          method="post"
          onSubmit={(e) => {
            e.preventDefault();
            void run(
              () => changePassword(locals.csrf, currentPassword, newPassword, confirmPassword),
              (vm) => {
                if (!vm.locals?.passwordError) {
                  setCurrentPassword('');
                  setNewPassword('');
                  setConfirmPassword('');
                  toast.success('Password updated');
                }
              },
            );
          }}
        >
          <label className="admin-label" htmlFor="current_password">Current password</label>
          <PasswordInput id="current_password" autoComplete="current-password" value={currentPassword} onChange={setCurrentPassword} />
          <label className="admin-label" htmlFor="new_password">New password</label>
          <PasswordInput id="new_password" autoComplete="new-password" minLength={passwordMinLength} placeholder={`At least ${passwordMinLength} characters`} value={newPassword} onChange={setNewPassword} />
          <label className="admin-label" htmlFor="confirm_password">Confirm new password</label>
          <PasswordInput id="confirm_password" autoComplete="new-password" minLength={passwordMinLength} value={confirmPassword} onChange={setConfirmPassword} />
          <button className="sso-button secondary" type="submit" disabled={busy}>Update password</button>
          <p className="sub" style={{ fontSize: 11, marginTop: 8 }}>Changing your password signs you out of every device, this one included.</p>
        </form>
      ) : (
        <p className="sub" style={{ margin: 0 }}>Your password is managed in Active Directory. Contact IT to change it.</p>
      )}

      <h3 className="admin-section-title">Where you are signed in</h3>
      {locals.mySessions.length === 0 ? (
        <p className="sub" style={{ margin: 0 }}>No live sessions found.</p>
      ) : (
        <div>
          {locals.mySessions.map((s) => (
            <div key={`${s.kind}:${s.key}`} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', padding: '9px 0', borderBottom: '1px solid var(--border)', fontSize: '12px' }}>
              <div>
                <strong>{SESSION_LABEL[s.kind] ?? s.kind}</strong>
                {s.current && <span style={{ color: 'var(--success-text)', fontWeight: 600 }}> — this device</span>}
                <div style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '2px' }}>
                  since {formatDateTime(s.createdAt)}
                  {s.expiresAt ? ` · expires ${formatDateTime(s.expiresAt)}` : ''}
                </div>
              </div>
              {!s.current && (
                <button type="button" disabled={busy} onClick={() => void run(() => killSession(locals.csrf, s.kind, s.key))} className="ui-btn ui-btn-sm ui-btn-danger">
                  Sign out
                </button>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="sub" style={{ fontSize: '11px', marginTop: '8px' }}>
        Signing out a session ends that device&apos;s access straight away. To end everything at once, use Sign out on the apps page.
      </p>

      <h3 className="admin-section-title">Recent sign-in activity</h3>
      {locals.recentLogins.length === 0 ? (
        <p className="sub" style={{ margin: 0 }}>No sign-in attempts recorded yet.</p>
      ) : (
        <div>
          {locals.recentLogins.map((l, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: '12px' }}>
              <span style={{ color: l.success ? (isNotableSuccess(l.success, l.reason) ? 'var(--warning-text)' : 'var(--success-text)') : 'var(--danger)', fontWeight: 600 }}>
                {loginReasonLabel(l.success, l.reason)}
              </span>
              <span style={{ color: 'var(--muted)' }}>{l.ip || '—'}</span>
              <span style={{ color: 'var(--muted)' }}>{formatDateTime(l.created_at)}</span>
            </div>
          ))}
        </div>
      )}
      <p className="sub" style={{ fontSize: '11px', marginTop: '8px' }}>See a sign-in you do not recognise? Change your password and tell your administrator.</p>
    </>
  );
}
