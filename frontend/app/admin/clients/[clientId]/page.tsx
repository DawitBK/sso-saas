'use client';

import { useMemo, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { adminFetch, ApiError } from '@shared/lib/adminApi';
import { formatDateTime } from '@shared/lib/format';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';

interface ClientUser {
  id: string;
  email: string;
  givenName: string;
  familyName: string;
  isActive: boolean;
  lastLoginAt: string | null;
  matchedGroups: string[];
  /** The roles the person holds in this application (managed applications only). */
  roles: string[];
}

interface ClientUsersData {
  clientId: string;
  name: string;
  /** Opened by holding one of its roles, not through a group. */
  managed: boolean;
  users: ClientUser[];
}

export default function ClientUsersPage() {
  const params = useParams();
  const clientId = String(params.clientId ?? '');
  const [filter, setFilter] = useState('');
  const query = useQuery({
    queryKey: ['admin-client-users', clientId],
    queryFn: () => adminFetch<ClientUsersData>(`/api/v1/admin/clients/${encodeURIComponent(clientId)}/users`),
    enabled: clientId !== '',
    staleTime: 0,
    retry: (count, err) => !(err instanceof ApiError && err.status === 404) && count < 1,
  });

  const users = useMemo(() => {
    const all = query.data?.users ?? [];
    const q = filter.trim().toLowerCase();
    return q ? all.filter((u) => `${u.email} ${u.givenName} ${u.familyName}`.toLowerCase().includes(q)) : all;
  }, [query.data, filter]);

  if (query.isPending) return <PageSkeleton rows={2} />;
  if (query.isError) {
    if (query.error instanceof ApiError && query.error.status === 404) {
      return (
        <div className="admin-card">
          <EmptyState title={`Unknown application “${clientId}”`} action={<Link href="/admin/clients" className="admin-btn secondary">Back to applications</Link>} />
        </div>
      );
    }
    return <ErrorState error={query.error} onRetry={() => query.refetch()} title="The list of people could not be loaded" />;
  }

  const data = query.data;
  return (
    <>
      <p className="sub" style={{ margin: '0 0 4px' }}>
        <Link href="/admin/clients" className="admin-link">← Applications</Link>
      </p>
      <div className="admin-page-header">
        <div>
          <h1>{data.name}</h1>
          <p>
            {data.managed ? (
              <>
                {data.users.length} {data.users.length === 1 ? 'person holds' : 'people hold'} a role in this application, and only they can sign in to it.
                Give or take away a role on the person&apos;s page; the roles on offer are edited under Applications.
              </>
            ) : (
              <>
                {data.users.length} {data.users.length === 1 ? 'person' : 'people'} may open this application: through a group it is
                granted to under Groups &gt; Access, or everybody who is signed in if no group has been given access.
              </>
            )}
          </p>
        </div>
      </div>

      <div className="admin-card">
        <div className="admin-search-bar">
          <label className="ui-field" style={{ flex: 1 }}>
            <span className="admin-visually-hidden">Filter people</span>
            <input className="ui-input" placeholder="Filter by name or email" value={filter} onChange={(e) => setFilter(e.target.value)} />
          </label>
        </div>
        {users.length === 0 ? (
          <EmptyState title={filter ? 'Nobody matches that filter' : 'Nobody has access yet'}>
            {filter ? 'Try a different name or address.' : 'Give a group access to this application under Groups, and its members appear here.'}
          </EmptyState>
        ) : (
          <table className="admin-table">
            <thead>
              <tr>
                <th>Email</th>
                <th>Name</th>
                <th>{data.managed ? 'Role' : 'Through'}</th>
                <th>Status</th>
                <th>Last sign-in</th>
                <th><span className="admin-visually-hidden">Open</span></th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.email}</td>
                  <td>{[user.givenName, user.familyName].filter(Boolean).join(' ') || '—'}</td>
                  <td style={{ fontSize: '12px', color: 'var(--muted)' }}>
                    {data.managed
                      ? (user.roles ?? []).join(', ')
                      : user.matchedGroups.length > 0
                        ? user.matchedGroups.map((dn) => <div key={dn} style={{ marginBottom: '2px' }}>{dn}</div>)
                        : 'open to everyone'}
                  </td>
                  <td>
                    <span className={`admin-badge ${user.isActive ? 'on' : 'off'}`}>{user.isActive ? 'Active' : 'Disabled'}</span>
                  </td>
                  <td style={{ color: 'var(--muted)' }}>{user.lastLoginAt ? formatDateTime(user.lastLoginAt) : 'never'}</td>
                  <td>
                    <Link href={`/admin/users/${user.id}`} className="admin-link">Manage →</Link>
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
