'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { adminFetch } from '@shared/lib/adminApi';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';

interface DmsRole {
  id: string;
  name: string;
  description: string | null;
}
interface DmsRolesData {
  roles: DmsRole[];
  error: string | null;
  /** Null unless the viewer is the platform administrator. */
  tenant: string | null;
}

export default function DmsRolesPage() {
  const [filter, setFilter] = useState('');
  const query = useQuery({
    queryKey: ['admin-dms-roles'],
    queryFn: () => adminFetch<DmsRolesData>('/api/v1/admin/dms-roles'),
    staleTime: 0,
  });

  const roles = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    const all = query.data?.roles ?? [];
    return needle ? all.filter((r) => r.name.toLowerCase().includes(needle) || (r.description ?? '').toLowerCase().includes(needle)) : all;
  }, [query.data?.roles, filter]);

  if (query.isPending) return <PageSkeleton rows={3} />;
  if (query.isError || !query.data) return <ErrorState error={query.error ?? new Error('The roles could not be loaded.')} onRetry={() => void query.refetch()} title="Could not load DMS roles" />;
  const data = query.data;

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>DMS Roles</h1>
          <p>
            What each role in the document system (DMS{data.tenant && <>, tenant <code className="admin-code">{data.tenant}</code></>}) may do by default.
            A change here applies to everyone who holds the role and has no personal exception; exceptions are set on that person&apos;s own page.
          </p>
        </div>
      </div>
      <div className="admin-card">
        {data.error ? (
          <ErrorState error={new Error(data.error)} onRetry={() => void query.refetch()} title="DMS did not return its roles" />
        ) : data.roles.length === 0 ? (
          <EmptyState title="DMS has no roles for this tenant">Nothing to edit yet. Roles are created in DMS itself.</EmptyState>
        ) : (
          <>
            <div className="admin-search-bar">
              <input className="ui-input" aria-label="Filter roles" placeholder="Filter roles by name or description" value={filter} onChange={(e) => setFilter(e.target.value)} style={{ flex: 1 }} />
              <span className="sub" style={{ alignSelf: 'center' }}>{roles.length} of {data.roles.length}</span>
            </div>
            {roles.length === 0 ? (
              <EmptyState title={`No role matches “${filter}”`}>Clear the filter to see every role.</EmptyState>
            ) : (
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Role</th>
                    <th>Description</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {roles.map((r) => (
                    <tr key={r.id}>
                      <td><strong>{r.name}</strong></td>
                      <td style={{ color: 'var(--muted)' }}>{r.description || '—'}</td>
                      <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                        <Link href={`/admin/dms-roles/detail?roleId=${encodeURIComponent(r.id)}`} className="admin-link">
                          Edit permissions →
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
      </div>
    </>
  );
}
