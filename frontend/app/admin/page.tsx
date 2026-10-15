'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';
import { ErrorState, PageSkeleton } from '@shared/ui/States';

interface DashboardData {
  userCount: number;
  /** Of userCount, how many are Active Directory accounts. */
  adUserCount?: number;
  groupCount: number;
  dmsConnected: boolean;
  health?: 'ready' | 'degraded' | 'not_ready';
  stats: {
    sso: number;
    portal: number;
    fails: number;
    audits: number;
  };
  alerts: Array<{ email: string; failures: number }>;
  clientUserCounts: Array<{ clientId: string; name: string; userCount: number }>;
}

export default function AdminDashboard() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<DashboardData | null>(null);

  useEffect(() => {
    fetch(apiPath('/api/v1/admin/stats'))
      .then((res) => res.json())
      // Response envelope is { data: {...}, meta } (see platform.router.ts's sendOk).
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load dashboard');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <PageSkeleton rows={2} />;
  }

  if (!data) {
    return <ErrorState error={new Error('The page could not be loaded. Check your connection and try again.')} onRetry={() => window.location.reload()} title="Could not load dashboard" />;
  }

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Admin console</h1>
          <p>Manage users, group memberships, app entitlements, and per-app roles.</p>
        </div>
      </div>

      {data.health && data.health !== 'ready' ? (
        <div className={`health-banner ${data.health}`} role="status">
          <strong>{data.health === 'degraded' ? 'Working, with something to look at.' : 'Sign-in is not available.'}</strong>
          <Link href="/admin/system" className="admin-link">See System health →</Link>
        </div>
      ) : null}

      <div className="admin-stat-grid">
        <div className="admin-card admin-stat-card">
          <div className="stat-label">Users</div>
          <div className="stat-value">{data.userCount}</div>
          {data.adUserCount !== undefined && (
            <p className="stat-foot">
              {data.userCount - data.adUserCount} local · {data.adUserCount} Active Directory
            </p>
          )}
          <p className="stat-foot">
            <Link href="/admin/users" className="admin-link">
              Manage users →
            </Link>
          </p>
        </div>
        <div className="admin-card admin-stat-card">
          <div className="stat-label">Known groups</div>
          <div className="stat-value">{data.groupCount}</div>
          <p className="stat-foot">
            <Link href="/admin/groups" className="admin-link">
              Manage access →
            </Link>
          </p>
        </div>
        <div className="admin-card admin-stat-card">
          <div className="stat-label">DMS internal API</div>
          <div className={`stat-value ${data.dmsConnected ? 'success' : 'danger'}`} style={{ fontSize: '17px' }}>
            {data.dmsConnected ? 'Connected' : 'Not configured'}
          </div>
          <p className="stat-foot">
            {data.dmsConnected
              ? 'DMS roles can be managed here.'
              : 'Set DMS_INTERNAL_API_KEY to manage DMS roles.'}
          </p>
        </div>
      </div>

      <h2 className="admin-section-title">Users per client</h2>
      <div className="admin-stat-grid">
        {data.clientUserCounts.map((client) => (
          <div key={client.clientId} className="admin-card admin-stat-card">
            <div className="stat-label">{client.name}</div>
            <div className="stat-value">{client.userCount}</div>
            <p className="stat-foot">
              <Link href={`/admin/clients/${client.clientId}`} className="admin-link">
                Manage users →
              </Link>
            </p>
          </div>
        ))}
      </div>

      <h2 className="admin-section-title">Right now</h2>
      <div className="admin-stat-grid">
        <div className="admin-card admin-stat-card">
          <div className="stat-label">Live SSO sessions</div>
          <div className="stat-value">{data.stats.sso}</div>
          <p className="stat-foot">
            <Link href="/admin/sessions" className="admin-link">
              Inspect / kill →
            </Link>
          </p>
        </div>
        <div className="admin-card admin-stat-card">
          <div className="stat-label">Portal sessions</div>
          <div className="stat-value">{data.stats.portal}</div>
          <p className="stat-foot">
            <Link href="/admin/sessions" className="admin-link">
              Inspect / kill →
            </Link>
          </p>
        </div>
        <div className="admin-card admin-stat-card">
          <div className="stat-label">Failed sign-ins (24h)</div>
          <div className={`stat-value ${Number(data.stats.fails) > 0 ? 'warning' : ''}`}>{data.stats.fails}</div>
          <p className="stat-foot">
            <Link href="/admin/logins" className="admin-link">
              Sign-in log →
            </Link>
          </p>
        </div>
        <div className="admin-card admin-stat-card">
          <div className="stat-label">Admin actions (7d)</div>
          <div className="stat-value">{data.stats.audits}</div>
          <p className="stat-foot">
            <Link href="/admin/audit" className="admin-link">
              Audit trail →
            </Link>
          </p>
        </div>
      </div>

      {data.alerts.length > 0 && (
        <div className="admin-card admin-alert-card">
          <p className="alert-title">⚠ Possible brute-force activity (≥5 failures in 15 min)</p>
          {data.alerts.map((alert) => (
            <p key={alert.email} className="alert-row">
              <Link href={`/admin/users?q=${encodeURIComponent(alert.email)}`}>
                <strong>{alert.email}</strong>
              </Link>{' '}
              — {alert.failures} failed attempts
            </p>
          ))}
        </div>
      )}

      <h2 className="admin-section-title">How this works</h2>
      <div className="admin-card">
        <p className="sub" style={{ margin: '0 0 10px' }}>
          Every user is put in one or more <strong>groups</strong>. Each group then gets, per app:
        </p>
        <p className="sub" style={{ margin: '0 0 4px' }}>
          1. An <strong>entitlement</strong> — can this group even open the app (shows on the portal)?
        </p>
        <p className="sub" style={{ margin: 0 }}>
          2. A <strong>role</strong> — what that group&apos;s members can do inside the app once they&apos;re in.
        </p>
      </div>
    </>
  );
}
