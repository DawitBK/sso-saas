'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface AuditEntry {
  id: string;
  created_at: string;
  actor_email: string;
  action: string;
  target: string;
  detail: Record<string, unknown> | null;
  ip: string | null;
}

interface AuditData {
  entries: AuditEntry[];
}

export default function AuditPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<AuditData | null>(null);

  useEffect(() => {
    // Backend truncates to a flat `limit`, not page-based pagination.
    fetch(apiPath('/api/v1/admin/audit?limit=100'))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load audit log');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load audit log</div>;
  }

  return (
    <>
      <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Audit Log</h1>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 20px' }}>
        Most recent 100 administrative actions.
      </p>

      <div className="admin-card">
        {data.entries.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No audit entries found.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
                <th>IP Address</th>
              </tr>
            </thead>
            <tbody>
              {data.entries.map((entry) => (
                <tr key={entry.id}>
                  <td style={{ color: 'var(--muted)', fontSize: '12px', fontFamily: 'monospace' }}>
                    {new Date(entry.created_at).toLocaleString()}
                  </td>
                  <td>{entry.actor_email}</td>
                  <td>
                    <code
                      style={{
                        fontSize: '12px',
                        background: 'var(--code-bg)',
                        padding: '2px 6px',
                        borderRadius: '6px',
                      }}
                    >
                      {entry.action}
                    </code>
                  </td>
                  <td style={{ fontSize: '12px' }}>{entry.target || '—'}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                    {entry.ip || '—'}
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
