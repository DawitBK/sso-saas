'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface Session {
  id: string;
  kind: string;
  account_id: string | null;
  email: string | null;
  created_at: string;
  expires_at: string | null;
}

interface SessionsData {
  sessions: Session[];
  csrf: string;
}

export default function SessionsPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<SessionsData | null>(null);

  useEffect(() => {
    fetch(apiPath('/api/v1/admin/sessions'))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load sessions');
        setLoading(false);
      });
  }, []);

  const handleKillSession = async (sessionId: string) => {
    if (!data || !confirm('Kill this session? The user will be signed out.')) {
      return;
    }

    try {
      const response = await fetch(apiPath('/api/v1/admin/sessions/revoke'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId, csrf: data.csrf }),
      });

      if (!response.ok) {
        throw new Error('Failed to kill session');
      }

      toast.success('Session killed');
      setData((prev) => (prev ? { ...prev, sessions: prev.sessions.filter((s) => s.id !== sessionId) } : prev));
    } catch {
      toast.error('Failed to kill session');
    }
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load sessions</div>;
  }

  return (
    <>
      <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Active Sessions</h1>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 20px' }}>
        Live SSO (oidc-provider) sessions — killing one signs that user out on
        their next request. Portal-only sessions aren&apos;t listed here.
      </p>

      <div className="admin-card">
        {data.sessions.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No active sessions.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Account ID</th>
                <th>Created</th>
                <th>Expires</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.sessions.map((session) => (
                <tr key={session.id}>
                  <td>{session.email || '—'}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{session.account_id || '—'}</td>
                  <td style={{ color: 'var(--muted)', fontSize: '12px' }}>
                    {new Date(session.created_at).toLocaleString()}
                  </td>
                  <td style={{ color: 'var(--muted)', fontSize: '12px' }}>
                    {session.expires_at ? new Date(session.expires_at).toLocaleString() : 'Never'}
                  </td>
                  <td>
                    <button
                      onClick={() => handleKillSession(session.id)}
                      className="admin-btn danger"
                      style={{ padding: '4px 10px', fontSize: '12px' }}
                    >
                      Kill
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
