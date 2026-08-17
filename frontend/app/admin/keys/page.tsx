'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { Copy } from 'lucide-react';
import { apiPath } from '@shared/apiPath';

interface KeyPair {
  kid: string;
  isActive: boolean;
  createdAt: string;
  retiredAt: string | null;
}

interface KeysData {
  keys: KeyPair[];
}

export default function KeysPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<KeysData | null>(null);
  // /jwks is same-origin now (next.config.ts rewrites it to the backend) — no
  // backend field for this, it's a well-known static path, computed here.
  // apiPath() adds the /sso basePath in production — omitting it here would
  // display a technically-unreachable URL to admins (the real endpoint lives
  // under /sso/jwks, not the bare origin).
  const [jwksUri, setJwksUri] = useState(apiPath('/jwks'));

  useEffect(() => {
    if (typeof window !== 'undefined') setJwksUri(`${window.location.origin}${apiPath('/jwks')}`);
    fetch(apiPath('/api/v1/admin/keys'))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load keys');
        setLoading(false);
      });
  }, []);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load keys</div>;
  }

  return (
    <>
      <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Signing Keys</h1>
      <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0 0 20px' }}>
        Public keys used to sign JWTs and verify tokens.
      </p>

      <div className="admin-card" style={{ marginBottom: '18px' }}>
        <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--muted)', marginBottom: '8px' }}>
          JWKS Endpoint
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <code
            style={{
              flex: 1,
              fontSize: '13px',
              background: 'var(--code-bg)',
              padding: '8px 12px',
              borderRadius: '8px',
              wordBreak: 'break-all',
            }}
          >
            {jwksUri}
          </code>
          <button
            onClick={() => copyToClipboard(jwksUri)}
            className="admin-btn secondary"
            style={{ padding: '8px', flexShrink: 0 }}
          >
            <Copy size={14} />
          </button>
        </div>
      </div>

      <div className="admin-card">
        {data.keys.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No keys found.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Key ID</th>
                <th>Algorithm</th>
                <th>Status</th>
                <th>Created</th>
                <th>Retired</th>
              </tr>
            </thead>
            <tbody>
              {data.keys.map((key) => (
                <tr key={key.kid}>
                  <td>
                    <code
                      style={{
                        fontSize: '12px',
                        background: 'var(--code-bg)',
                        padding: '2px 6px',
                        borderRadius: '6px',
                      }}
                    >
                      {key.kid}
                    </code>
                  </td>
                  {/* Every key is RS256/RSA-2048 (jwks.ts's generateSigningKey) — no
                      per-key variation exists to show. */}
                  <td>RS256</td>
                  <td>
                    <span className={`badge ${key.isActive ? 'on' : 'off'}`}>
                      {key.isActive ? 'Active' : 'Retired'}
                    </span>
                  </td>
                  <td style={{ color: 'var(--muted)' }}>
                    {new Date(key.createdAt).toLocaleDateString()}
                  </td>
                  <td style={{ color: 'var(--muted)' }}>
                    {key.retiredAt ? new Date(key.retiredAt).toLocaleDateString() : '—'}
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
