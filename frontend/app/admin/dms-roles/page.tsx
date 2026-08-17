'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface DmsRole {
  id: string;
  name: string;
  description: string | null;
}
interface DmsRolesData {
  roles: DmsRole[];
  error: string | null;
  tenant: string;
}

export default function DmsRolesPage() {
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<DmsRolesData | null>(null);

  useEffect(() => {
    fetch(apiPath('/api/v1/admin/dms-roles'))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load DMS roles');
        setLoading(false);
      });
  }, []);

  if (loading) return <div>Loading...</div>;
  if (!data) return <div>Failed to load DMS roles</div>;

  return (
    <>
      <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>DMS Roles</h1>
      <p className="sub" style={{ margin: '0 0 20px' }}>
        Default permissions per DMS (EDAMS) role — tenant <code className="admin-code">{data.tenant}</code>. Changes
        here affect every user with this role who has no per-user override (set on that user&apos;s own page).
      </p>
      <div className="admin-card">
        {data.error ? (
          <p style={{ margin: 0, color: 'var(--danger)' }}>{data.error}</p>
        ) : data.roles.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No roles found.</p>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Role</th>
                <th>Description</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.roles.map((r) => (
                <tr key={r.id}>
                  <td>
                    <strong>{r.name}</strong>
                  </td>
                  <td style={{ color: 'var(--muted)' }}>{r.description || '—'}</td>
                  <td style={{ textAlign: 'right' }}>
                    <Link href={`/admin/dms-roles/detail?roleId=${encodeURIComponent(r.id)}`} className="admin-link">
                      Edit permissions →
                    </Link>
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
