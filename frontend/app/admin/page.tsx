'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface DashboardData {
  userCount: number;
  groupCount: number;
  dmsConnected: boolean;
  stats: {
    sso: number;
    portal: number;
    fails: number;
    audits: number;
  };
  alerts: Array<{ email: string; failures: number }>;
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
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load dashboard</div>;
  }

  return (
    <>
      <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Admin console</h1>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 20px' }}>
        Manage local users, group memberships, app entitlements, and per-app roles.
      </p>

      <div style={{ display: 'flex', gap: '16px', marginBottom: '28px', flexWrap: 'wrap' }}>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>Local users</div>
          <div style={{ fontSize: '28px', fontWeight: 700 }}>{data.userCount}</div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            <Link href="/admin/users" className="admin-link">
              Manage users →
            </Link>
          </p>
        </div>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>Known groups</div>
          <div style={{ fontSize: '28px', fontWeight: 700 }}>{data.groupCount}</div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            <Link href="/admin/groups" className="admin-link">
              Manage access →
            </Link>
          </p>
        </div>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>DMS internal API</div>
          <div style={{ fontSize: '15px', fontWeight: 700, color: data.dmsConnected ? '#166534' : '#b91c1c' }}>
            {data.dmsConnected ? 'Connected' : 'Not configured'}
          </div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            {data.dmsConnected
              ? 'DMS roles can be managed here.'
              : 'Set DMS_INTERNAL_API_KEY to manage DMS roles.'}
          </p>
        </div>
      </div>

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>Right now</h2>
      <div style={{ display: 'flex', gap: '16px', marginBottom: '28px', flexWrap: 'wrap' }}>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>Live SSO sessions</div>
          <div style={{ fontSize: '28px', fontWeight: 700 }}>{data.stats.sso}</div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            <Link href="/admin/sessions" className="admin-link">
              Inspect / kill →
            </Link>
          </p>
        </div>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>Portal sessions</div>
          <div style={{ fontSize: '28px', fontWeight: 700 }}>{data.stats.portal}</div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            <Link href="/admin/sessions" className="admin-link">
              Inspect / kill →
            </Link>
          </p>
        </div>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>Failed sign-ins (24h)</div>
          <div
            style={{
              fontSize: '28px',
              fontWeight: 700,
              color: Number(data.stats.fails) > 0 ? '#b45309' : 'inherit',
            }}
          >
            {data.stats.fails}
          </div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            <Link href="/admin/logins" className="admin-link">
              Sign-in log →
            </Link>
          </p>
        </div>
        <div className="admin-card" style={{ flex: 1, minWidth: '200px' }}>
          <div style={{ fontSize: '12px', marginBottom: '6px', color: 'var(--muted)' }}>Admin actions (7d)</div>
          <div style={{ fontSize: '28px', fontWeight: 700 }}>{data.stats.audits}</div>
          <p className="sub" style={{ margin: '6px 0 0' }}>
            <Link href="/admin/audit" className="admin-link">
              Audit trail →
            </Link>
          </p>
        </div>
      </div>

      {data.alerts.length > 0 && (
        <div
          className="admin-card"
          style={{ borderColor: '#fecaca', background: '#fef2f2', marginTop: '16px' }}
        >
          <p style={{ margin: '0 0 8px', fontWeight: 700, color: '#b91c1c', fontSize: '13px' }}>
            ⚠ Possible brute-force activity (≥5 failures in 15 min)
          </p>
          {data.alerts.map((alert) => (
            <p key={alert.email} className="sub" style={{ margin: 0, color: '#7f1d1d' }}>
              <Link
                href={`/admin/users?q=${encodeURIComponent(alert.email)}`}
                className="admin-link"
                style={{ color: '#7f1d1d' }}
              >
                <strong>{alert.email}</strong>
              </Link>{' '}
              — {alert.failures} failed attempts
            </p>
          ))}
        </div>
      )}

      <h2 style={{ fontSize: '16px', margin: '28px 0 10px' }}>How this works</h2>
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
