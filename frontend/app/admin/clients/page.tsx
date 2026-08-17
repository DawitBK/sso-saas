'use client';

import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface Client {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  created_at: string;
}

interface ClientsData {
  clients: Client[];
}

export default function ClientsPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<ClientsData | null>(null);

  useEffect(() => {
    fetch(apiPath('/api/v1/admin/clients'))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load clients');
        setLoading(false);
      });
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load clients</div>;
  }

  return (
    <>
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>OAuth Clients</h1>
        <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0' }}>
          Registered applications that can authenticate via SSO. Managed via
          `idp_clients` / `config.ts`&apos;s client seed, not from this console yet.
        </p>
      </div>

      <div className="admin-card">
        {data.clients.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No OAuth clients registered.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Client ID</th>
                <th>Name</th>
                <th>Grant Types</th>
                <th>Redirect URIs</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {data.clients.map((client) => (
                <tr key={client.client_id}>
                  <td>
                    <code
                      style={{
                        fontSize: '12px',
                        background: 'var(--code-bg)',
                        padding: '2px 6px',
                        borderRadius: '6px',
                        wordBreak: 'break-all',
                      }}
                    >
                      {client.client_id}
                    </code>
                  </td>
                  <td style={{ fontWeight: 600 }}>{client.client_name}</td>
                  <td style={{ fontSize: '12px' }}>
                    {client.grant_types.join(', ')}
                  </td>
                  <td style={{ fontSize: '12px', maxWidth: '200px' }}>
                    {client.redirect_uris.length} URI{client.redirect_uris.length !== 1 ? 's' : ''}
                  </td>
                  <td style={{ color: 'var(--muted)' }}>
                    {new Date(client.created_at).toLocaleDateString()}
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
