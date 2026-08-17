'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface LoginAttempt {
  id: string;
  email: string;
  success: boolean;
  reason: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
}

interface LoginsData {
  logins: LoginAttempt[];
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}

export default function LoginsPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<LoginsData | null>(null);
  const [page, setPage] = useState(1);
  const [filter, setFilter] = useState<'all' | 'success' | 'failed'>('all');

  useEffect(() => {
    const params = new URLSearchParams();
    params.set('page', page.toString());
    if (filter !== 'all') params.set('filter', filter);

    fetch(apiPath(`/api/v1/admin/logins?${params.toString()}`))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load login history');
        setLoading(false);
      });
  }, [page, filter]);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load login history</div>;
  }

  return (
    <>
      <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Sign-in History</h1>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 20px' }}>
        Recent authentication attempts (last 30 days).
      </p>

      <div className="admin-card">
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
          <button
            onClick={() => setFilter('all')}
            className={`admin-btn ${filter === 'all' ? '' : 'secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            All
          </button>
          <button
            onClick={() => setFilter('success')}
            className={`admin-btn ${filter === 'success' ? '' : 'secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            Success
          </button>
          <button
            onClick={() => setFilter('failed')}
            className={`admin-btn ${filter === 'failed' ? '' : 'secondary'}`}
            style={{ fontSize: '12px', padding: '6px 12px' }}
          >
            Failed
          </button>
        </div>

        {data.logins.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No login attempts found.</p>
        ) : (
          <>
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Email</th>
                  <th>Result</th>
                  <th>IP Address</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {data.logins.map((attempt) => (
                  <tr key={attempt.id}>
                    <td style={{ color: 'var(--muted)', fontSize: '12px', fontFamily: 'monospace' }}>
                      {new Date(attempt.created_at).toLocaleString()}
                    </td>
                    <td>{attempt.email}</td>
                    <td>
                      <span className={`badge ${attempt.success ? 'on' : 'off'}`}>
                        {attempt.success ? 'Success' : 'Failed'}
                      </span>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                      {attempt.ip || '—'}
                    </td>
                    <td style={{ fontSize: '12px', color: 'var(--muted)' }}>
                      {attempt.reason || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {data.pagination.totalPages > 1 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '14px' }}>
                {data.pagination.page > 1 && (
                  <button
                    onClick={() => setPage(data.pagination.page - 1)}
                    className="admin-btn secondary"
                  >
                    ← Prev
                  </button>
                )}
                <span style={{ color: 'var(--muted)', fontSize: '12px' }}>
                  Page {data.pagination.page} of {data.pagination.totalPages} ({data.pagination.total} attempts)
                </span>
                {data.pagination.page < data.pagination.totalPages && (
                  <button
                    onClick={() => setPage(data.pagination.page + 1)}
                    className="admin-btn secondary"
                  >
                    Next →
                  </button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
