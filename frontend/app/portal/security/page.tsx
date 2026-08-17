'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import {
  getSecurityState,
  totpStart,
  totpConfirm,
  totpDisable,
  changePassword,
  killSession,
  type SecurityViewModel,
} from './actions';

export default function SecurityPage() {
  const [loading, setLoading] = useState(true);
  const [locals, setLocals] = useState<SecurityViewModel['locals'] | null>(null);
  const [busy, setBusy] = useState(false);

  const [totpCode, setTotpCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const apply = (vm: SecurityViewModel) => {
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
    if (vm.locals.error) toast.error(vm.locals.error);
    if (vm.locals.passwordError) toast.error(vm.locals.passwordError);
    setLoading(false);
  };

  const refresh = () => {
    setLoading(true);
    getSecurityState().then(apply).catch(() => {
      toast.error('Could not load security settings.');
      setLoading(false);
    });
  };

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) return <div>Loading...</div>;
  if (!locals) return <div className="sso-error">Could not load security settings.</div>;

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
        <div>
          <h2 style={{ marginBottom: '2px' }}>Security</h2>
          <p className="sub" style={{ margin: 0 }}>
            {locals.userEmail}
          </p>
        </div>
        <Link href="/portal" className="admin-link" style={{ fontSize: '12px' }}>
          ← Back to apps
        </Link>
      </div>

      {locals.pending ? (
        <>
          <p className="sub" style={{ marginTop: '16px' }}>
            <strong>1.</strong> In your authenticator app (Google Authenticator, Authy, …) choose &quot;Enter a setup
            key&quot; and add:
          </p>
          <p
            style={{
              fontFamily: 'ui-monospace,monospace',
              fontSize: '15px',
              letterSpacing: '.12em',
              background: 'var(--code-bg, #f1f5f9)',
              padding: '10px 12px',
              borderRadius: '10px',
              wordBreak: 'break-all',
            }}
          >
            {locals.pending.secret}
          </p>
          <p className="sub" style={{ fontSize: '11px', wordBreak: 'break-all' }}>
            or use this URI: {locals.pending.uri}
          </p>
          <p className="sub">
            <strong>2.</strong> Enter the 6-digit code the app shows to finish:
          </p>
          <form
            autoComplete="off"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                apply(await totpConfirm(locals.csrf, totpCode));
                setTotpCode('');
              } catch {
                toast.error('Something went wrong. Please try again.');
              } finally {
                setBusy(false);
              }
            }}
          >
            <input
              className="sso-input"
              type="text"
              inputMode="numeric"
              maxLength={6}
              required
              autoFocus
              placeholder="000000"
              style={{ letterSpacing: '.4em', textAlign: 'center', fontSize: '18px', fontFamily: 'ui-monospace,monospace' }}
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value)}
            />
            <button className="sso-button" type="submit" disabled={busy}>
              Turn on two-factor auth
            </button>
          </form>
        </>
      ) : locals.mfaEnabled ? (
        <>
          <p className="sub" style={{ marginTop: '16px' }}>
            Two-factor authentication is <strong style={{ color: '#166534' }}>ON</strong> — every sign-in asks for a
            code from your app.
          </p>
          <p className="sub">To turn it off, confirm with a current code:</p>
          <form
            autoComplete="off"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                apply(await totpDisable(locals.csrf, disableCode));
                setDisableCode('');
              } catch {
                toast.error('Something went wrong. Please try again.');
              } finally {
                setBusy(false);
              }
            }}
          >
            <input
              className="sso-input"
              type="text"
              inputMode="numeric"
              maxLength={6}
              required
              placeholder="000000"
              style={{ letterSpacing: '.4em', textAlign: 'center', fontSize: '18px', fontFamily: 'ui-monospace,monospace' }}
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value)}
            />
            <button className="sso-button secondary" type="submit" disabled={busy} style={{ borderColor: '#fecaca', color: '#b91c1c' }}>
              Turn off two-factor auth
            </button>
          </form>
          <p className="sub" style={{ fontSize: '11px', marginTop: '10px' }}>
            Lost your device? Ask an administrator to reset two-factor auth for your account.
          </p>
        </>
      ) : (
        <>
          <p className="sub" style={{ marginTop: '16px' }}>
            Two-factor authentication is <strong>off</strong>. With it on, signing in requires your password{' '}
            <em>and</em> a 6-digit code from an authenticator app.
          </p>
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              try {
                apply(await totpStart(locals.csrf));
              } catch {
                toast.error('Something went wrong. Please try again.');
              } finally {
                setBusy(false);
              }
            }}
          >
            <button className="sso-button" type="submit" disabled={busy}>
              Set up two-factor auth
            </button>
          </form>
        </>
      )}

      <p style={{ fontWeight: 700, fontSize: '12px', margin: '26px 0 8px', textTransform: 'uppercase', letterSpacing: '.05em', color: 'var(--muted)' }}>
        Password
      </p>
      {locals.canChangePassword ? (
        <form
          autoComplete="off"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            try {
              const vm = await changePassword(locals.csrf, currentPassword, newPassword, confirmPassword);
              apply(vm);
              if (!vm.locals?.passwordError) {
                setCurrentPassword('');
                setNewPassword('');
                setConfirmPassword('');
                toast.success('Password updated');
              }
            } catch {
              toast.error('Something went wrong. Please try again.');
            } finally {
              setBusy(false);
            }
          }}
        >
          <label className="admin-label" htmlFor="current_password">
            Current password
          </label>
          <input
            id="current_password"
            className="sso-input"
            type="password"
            required
            autoComplete="current-password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <label className="admin-label" htmlFor="new_password">
            New password
          </label>
          <input
            id="new_password"
            className="sso-input"
            type="password"
            required
            minLength={8}
            autoComplete="new-password"
            placeholder="At least 8 characters"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <label className="admin-label" htmlFor="confirm_password">
            Confirm new password
          </label>
          <input
            id="confirm_password"
            className="sso-input"
            type="password"
            required
            minLength={8}
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
          <button className="sso-button secondary" type="submit" disabled={busy}>
            Update password
          </button>
        </form>
      ) : (
        <p className="sub" style={{ margin: 0 }}>
          Your password is managed outside the IdP (Active Directory) — contact IT to change it.
        </p>
      )}

      <p style={{ fontWeight: 700, fontSize: '12px', margin: '26px 0 8px', textTransform: 'uppercase', letterSpacing: '.05em', color: 'var(--muted)' }}>
        Your active sessions
      </p>
      {locals.mySessions.length === 0 ? (
        <p className="sub" style={{ margin: 0 }}>
          No live sessions found.
        </p>
      ) : (
        <div>
          {locals.mySessions.map((s) => (
            <div
              key={`${s.kind}:${s.key}`}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', padding: '9px 0', borderBottom: '1px solid var(--border)', fontSize: '12px' }}
            >
              <div>
                <strong style={{ textTransform: 'capitalize' }}>{s.kind}</strong>
                {s.current && <span style={{ color: '#166534', fontWeight: 600 }}> — this device</span>}
                <div style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '2px' }}>
                  since {new Date(s.createdAt).toLocaleString()}
                  {s.expiresAt ? ` · expires ${new Date(s.expiresAt).toLocaleString()}` : ''}
                </div>
              </div>
              {!s.current && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={async () => {
                    setBusy(true);
                    try {
                      apply(await killSession(locals.csrf, s.kind, s.key));
                    } catch {
                      toast.error('Something went wrong. Please try again.');
                    } finally {
                      setBusy(false);
                    }
                  }}
                  style={{ width: 'auto', margin: 0, padding: '6px 10px', fontSize: '11px', borderRadius: '8px', border: '1px solid #fecaca', background: '#fff', color: '#b91c1c', cursor: 'pointer' }}
                >
                  Sign out
                </button>
              )}
            </div>
          ))}
        </div>
      )}
      <p className="sub" style={{ fontSize: '11px', marginTop: '8px' }}>
        Signing out a session ends that device&apos;s access immediately. To end everything at once, use Sign out on
        the apps page.
      </p>

      <p style={{ fontWeight: 700, fontSize: '12px', margin: '26px 0 8px', textTransform: 'uppercase', letterSpacing: '.05em', color: 'var(--muted)' }}>
        Recent sign-in activity
      </p>
      {locals.recentLogins.length === 0 ? (
        <p className="sub" style={{ margin: 0 }}>
          No sign-in attempts recorded yet.
        </p>
      ) : (
        <div>
          {locals.recentLogins.map((l, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', padding: '6px 0', borderBottom: '1px solid var(--border)', fontSize: '12px' }}>
              <span style={{ color: l.success ? '#166534' : '#b91c1c', fontWeight: 600 }}>{l.success ? 'Success' : l.reason || 'Failed'}</span>
              <span style={{ color: 'var(--muted)' }}>{l.ip || '—'}</span>
              <span style={{ color: 'var(--muted)' }}>{new Date(l.created_at).toLocaleString()}</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
