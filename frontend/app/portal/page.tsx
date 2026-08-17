'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useThemeStore, type Theme } from '../../state/theme.store';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';
import { InstallAppButton } from '@shared/components/InstallAppButton';

interface Application {
  name: string;
  url: string;
  mode: string;
}

interface PortalData {
  userName: string;
  userEmail: string;
  isAdmin: boolean;
  apps: Application[];
  csrf: string;
}

export default function PortalPage() {
  const { theme, setTheme } = useThemeStore();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<PortalData | null>(null);

  useEffect(() => {
    fetch(apiPath('/api/v1/portal'))
      .then(async (res) => {
        if (res.status === 401) {
          // No active portal session — kick off the real SSO auth-code+PKCE
          // flow (portal/router.ts's own /login), not a bare client-side page
          // with no interaction context.
          // apiPath, not a bare path: window.location is NOT basePath-aware
          // (unlike next/link and router.push), so under /sso this would
          // navigate to portal.examplecorp.com/portal/login and 404 at the reverse proxy.
          window.location.href = apiPath('/portal/login');
          return null;
        }
        return res.json();
      })
      .then((json) => {
        if (!json) return; // redirecting
        // Response envelope is { data: { user: { name, email, isAdmin }, apps, csrf }, meta }.
        const body = json.data ?? json;
        setData({
          userName: body.user?.name ?? '',
          userEmail: body.user?.email ?? '',
          isAdmin: Boolean(body.user?.isAdmin),
          apps: body.apps ?? [],
          csrf: body.csrf ?? '',
        });
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load portal');
        setLoading(false);
      });
  }, []);

  const handleThemeChange = (newTheme: Theme) => {
    setTheme(newTheme);
  };

  const handleSignOut = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      // Direct fetch to the real backend path (proxied same-origin by
      // next.config.ts's rewrite) — NOT a separate /api/proxy/* route. The
      // CSRF cookie portal/router.ts issues is scoped to Path=/portal, so it
      // only ever gets sent to requests under /portal/*; routing this through
      // any other path silently drops it and the CSRF check always fails.
      // fetch() follows the resulting redirect chain (session/end -> back to
      // /portal) automatically since every hop is same-origin.
      const res = await fetch(apiPath('/portal/logout'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf: data?.csrf ?? '' }).toString(),
      });
      window.location.href = res.url || apiPath('/portal');
    } catch {
      toast.error('Failed to sign out');
    }
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div>Loading...</div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="portal-layout">
      {/* Left brand panel */}
      <div className="portal-brand-panel">
        <div className="logo">
          <div className="dot">K</div>
          <div className="text" style={{ display: 'flex', flexDirection: 'column' }}>
            <h2 style={{ fontSize: '16px', fontWeight: 700, color: '#f1f5f9', margin: 0, letterSpacing: '-0.02em' }}>
              Example Corp Identity
            </h2>
            <p style={{ fontSize: '11px', color: '#64748b', margin: '2px 0 0' }}>Single sign-on</p>
          </div>
        </div>
        <div className="hero" style={{ marginTop: '60px' }}>
          <h1 style={{ fontSize: '26px', fontWeight: 700, color: '#e2e8f0', lineHeight: 1.3, letterSpacing: '-0.03em', margin: '0 0 12px' }}>
            Your applications,<br />one secure gateway.
          </h1>
          <p style={{ fontSize: '14px', color: '#94a3b8', lineHeight: 1.6, margin: 0 }}>
            Access all your enterprise applications with a single sign-in. No more remembering multiple passwords.
          </p>
          <div className="features" style={{ marginTop: '32px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div className="feat" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--brand)', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: '#94a3b8' }}>Unified identity across all systems</span>
            </div>
            <div className="feat" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--brand)', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: '#94a3b8' }}>OpenID Connect &amp; OAuth 2.0 secured</span>
            </div>
            <div className="feat" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--brand)', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: '#94a3b8' }}>Session management &amp; audit logging</span>
            </div>
            <div className="feat" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--brand)', flexShrink: 0 }} />
              <span style={{ fontSize: '13px', color: '#94a3b8' }}>Multi-factor authentication ready</span>
            </div>
          </div>
        </div>
        <div className="footer" style={{ fontSize: '11px', color: '#334155' }}>
          © Example Corp · Secured by OpenID Connect
        </div>
      </div>

      {/* Main content */}
      <div className="portal-main">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '40px', gap: '16px', flexWrap: 'wrap' }}>
          <div className="greeting">
            <h1 style={{ fontSize: '22px', fontWeight: 700, color: 'var(--ink)', margin: 0, letterSpacing: '-0.02em' }}>
              Welcome, {data.userName}
            </h1>
            <p style={{ fontSize: '13px', color: 'var(--muted)', margin: '4px 0 0' }}>{data.userEmail}</p>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
            {data.isAdmin && (
              <Link
                href="/admin"
                style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: 'var(--brand)',
                  textDecoration: 'none',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: '1px solid var(--border)',
                  background: 'var(--card)',
                  cursor: 'pointer',
                  transition: 'all .12s ease',
                  whiteSpace: 'nowrap',
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '38px',
                }}
              >
                Admin Console
              </Link>
            )}
            <InstallAppButton />
            <Link
              href="/portal/security"
              style={{
                fontSize: '13px',
                fontWeight: 600,
                color: 'var(--brand)',
                textDecoration: 'none',
                padding: '8px 16px',
                borderRadius: '8px',
                border: '1px solid var(--border)',
                background: 'var(--card)',
                cursor: 'pointer',
                transition: 'all .12s ease',
                whiteSpace: 'nowrap',
                display: 'inline-flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '38px',
              }}
            >
              Security Settings
            </Link>
            <form onSubmit={handleSignOut}>
              <button
                type="submit"
                style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: 'var(--danger)',
                  textDecoration: 'none',
                  padding: '8px 16px',
                  borderRadius: '8px',
                  border: '1px solid var(--danger-border)',
                  background: 'var(--danger-bg)',
                  cursor: 'pointer',
                  transition: 'all .12s ease',
                  whiteSpace: 'nowrap',
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  height: '38px',
                }}
              >
                Sign out
              </button>
            </form>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 10px', borderRadius: '8px', border: '1px solid var(--border)', background: 'var(--card)', height: '38px' }}>
              <button
                type="button"
                className={`theme-dot light ${theme === 'light' ? 'active' : ''}`}
                onClick={() => handleThemeChange('light')}
                aria-label="Light theme"
                title="Light"
                style={{ width: '16px', height: '16px' }}
              />
              <button
                type="button"
                className={`theme-dot dark-black ${theme === 'dark-black' ? 'active' : ''}`}
                onClick={() => handleThemeChange('dark-black')}
                aria-label="Black theme"
                title="Black"
                style={{ width: '16px', height: '16px' }}
              />
              <button
                type="button"
                className={`theme-dot dark-blue ${theme === 'dark-blue' ? 'active' : ''}`}
                onClick={() => handleThemeChange('dark-blue')}
                aria-label="Blue theme"
                title="Blue"
                style={{ width: '16px', height: '16px' }}
              />
            </div>
          </div>
        </div>

        <p style={{ fontSize: '13px', fontWeight: 600, color: 'var(--muted)', marginBottom: '16px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Your Applications
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '8px' }}>
          {data.apps
            .filter((app) => app.name !== 'Retail OS')
            .map((app) => (
              <a
                key={app.name}
                className={`portal-app-item ${app.mode === 'Soon' ? 'disabled' : ''}`}
                href={app.url}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <span style={{ fontWeight: 600, fontSize: '14px', color: 'var(--ink)' }}>{app.name}</span>
                  <span style={{ fontSize: '12px', color: 'var(--muted)' }}>
                    {app.mode === 'Soon' ? 'Coming soon' : 'Click to open'}
                  </span>
                </div>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--brand)' }}>
                  {app.mode} →
                </span>
              </a>
            ))}
        </div>
      </div>
    </div>
  );
}
