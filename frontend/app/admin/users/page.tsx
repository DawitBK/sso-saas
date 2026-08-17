'use client';

import { Suspense, useEffect, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import toast from 'react-hot-toast';
import { apiPath } from '@shared/apiPath';

interface User {
  id: string;
  email: string;
  given_name: string | null;
  family_name: string | null;
  group_count: number;
  is_active: boolean;
  last_login_at: string | null;
}

interface UsersData {
  users: User[];
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}

export default function UsersPage() {
  return (
    <Suspense fallback={<div>Loading...</div>}>
      <UsersPageInner />
    </Suspense>
  );
}

function UsersPageInner() {
  const searchParams = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<UsersData | null>(null);
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');

  const page = parseInt(searchParams.get('page') || '1');
  const q = searchParams.get('q') || '';

  useEffect(() => {
    const query = new URLSearchParams();
    if (q) query.set('q', q);
    if (page > 1) query.set('page', page.toString());

    fetch(apiPath(`/api/v1/admin/users?${query.toString()}`))
      .then((res) => res.json())
      .then((json) => {
        setData(json.data ?? null);
        setLoading(false);
      })
      .catch(() => {
        toast.error('Failed to load users');
        setLoading(false);
      });
  }, [q, page]);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!data) {
    return <div>Failed to load users</div>;
  }

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <div>
          <h1 style={{ fontSize: '20px', margin: '0 0 4px' }}>Users</h1>
          <p className="sub" style={{ color: 'var(--muted)', fontSize: '13px', margin: '0' }}>
            Local IdP accounts (AD users authenticate directly and don&apos;t appear here).
          </p>
        </div>
        <Link href="/admin/users/new" className="admin-btn">
          + New user
        </Link>
      </div>

      <div className="admin-card">
        <form
          method="get"
          // apiPath: a form action is not basePath-aware (only next/link is).
          action={apiPath('/admin/users')}
          style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', flexWrap: 'wrap', marginBottom: data.users.length ? '14px' : '0' }}
        >
          <input
            type="text"
            name="q"
            placeholder="Search by email"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              padding: '9px 10px',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              fontSize: '13px',
              background: 'var(--input-bg)',
              color: 'var(--ink)',
              flex: 1,
              minWidth: '200px',
            }}
          />
          <button className="admin-btn secondary" type="submit">
            Search
          </button>
        </form>

        {data.users.length === 0 ? (
          <p style={{ color: 'var(--muted)' }}>No users found.</p>
        ) : (
          <>
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Name</th>
                  <th>Groups</th>
                  <th>Status</th>
                  <th>Last login</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {data.users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.email}</td>
                    <td>
                      {[user.given_name, user.family_name].filter(Boolean).join(' ') || '—'}
                    </td>
                    <td>{user.group_count}</td>
                    <td>
                      <span className={`badge ${user.is_active ? 'on' : 'off'}`}>
                        {user.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ color: 'var(--muted)' }}>
                      {user.last_login_at
                        ? new Date(user.last_login_at).toLocaleString()
                        : 'never'}
                    </td>
                    <td>
                      <Link href={`/admin/users/${user.id}`} className="admin-link">
                        Manage →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {data.pagination.totalPages > 1 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginTop: '14px' }}>
                {data.pagination.page > 1 && (
                  <Link
                    href={`/admin/users?q=${encodeURIComponent(q)}&page=${data.pagination.page - 1}`}
                    className="admin-btn secondary"
                  >
                    ← Prev
                  </Link>
                )}
                <span style={{ color: 'var(--muted)', fontSize: '12px' }}>
                  Page {data.pagination.page} of {data.pagination.totalPages} ({data.pagination.total} users)
                </span>
                {data.pagination.page < data.pagination.totalPages && (
                  <Link
                    href={`/admin/users?q=${encodeURIComponent(q)}&page=${data.pagination.page + 1}`}
                    className="admin-btn secondary"
                  >
                    Next →
                  </Link>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
