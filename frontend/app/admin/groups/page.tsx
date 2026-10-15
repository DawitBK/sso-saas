'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { adminFetch } from '@shared/lib/adminApi';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';
import { groupName } from './groupName';

interface Group {
  dn: string;
  memberCount: number;
  apps: Array<{ rp: string; label: string }>;
}

interface GroupsData {
  groups: Group[];
  filters: { q: string };
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}

export default function GroupsPage() {
  return (
    <Suspense fallback={<PageSkeleton rows={2} />}>
      <GroupsPageInner />
    </Suspense>
  );
}

function GroupsPageInner() {
  const router = useRouter();
  const params = useSearchParams();
  const page = Math.max(1, parseInt(params.get('page') || '1'));
  const q = params.get('q') || '';
  const [draft, setDraft] = useState(q);

  const go = (over: { q?: string; page?: number }) => {
    const out = new URLSearchParams();
    const nextQ = over.q ?? q;
    const nextPage = over.page ?? 1;
    if (nextQ) out.set('q', nextQ);
    if (nextPage > 1) out.set('page', String(nextPage));
    router.push(out.toString() ? `/admin/groups?${out}` : '/admin/groups');
  };

  const query = useQuery({
    queryKey: ['admin-groups', page, q],
    queryFn: () => adminFetch<GroupsData>(`/api/v1/admin/groups?page=${page}${q ? `&q=${encodeURIComponent(q)}` : ''}`),
    placeholderData: keepPreviousData,
    staleTime: 0,
  });

  if (query.isPending) return <PageSkeleton rows={3} />;
  if (query.isError || !query.data) return <ErrorState error={query.error ?? new Error('The groups could not be loaded.')} onRetry={() => void query.refetch()} title="Could not load groups" />;
  const data = query.data;

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Groups</h1>
          <p>
            A group is what ties people to applications: everyone in it can open the applications it is entitled to, with the role it maps to in DMS and GMS.
            Every group that has members, an application, or a role mapping appears here.
          </p>
        </div>
      </div>

      <div className="admin-card">
        <form
          className="admin-search-bar"
          onSubmit={(e) => {
            e.preventDefault();
            go({ q: draft.trim() });
          }}
        >
          <input className="ui-input" aria-label="Search groups" placeholder="Search by group name" value={draft} onChange={(e) => setDraft(e.target.value)} style={{ flex: 1 }} />
          <button type="submit" className="admin-btn secondary">Search</button>
          {q ? (
            <button type="button" className="admin-btn secondary" onClick={() => { setDraft(''); go({ q: '' }); }}>Clear</button>
          ) : null}
        </form>

        {data.groups.length === 0 ? (
          q ? (
            <EmptyState title={`No group matches “${q}”`}>Check the spelling, or clear the search to see every group.</EmptyState>
          ) : (
            <EmptyState title="No groups yet">Add a person to a group from their user page, and the group appears here.</EmptyState>
          )
        ) : (
          <>
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Members</th>
                  <th>Opens</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.groups.map((group) => (
                  <tr key={group.dn}>
                    <td>
                      <strong>{groupName(group.dn)}</strong>
                      <div className="sub"><code className="admin-code" style={{ fontSize: 11 }}>{group.dn}</code></div>
                    </td>
                    <td>{group.memberCount}</td>
                    <td>
                      {group.apps.length === 0 ? (
                        <span className="sub">No application yet</span>
                      ) : (
                        <span style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap' }}>
                          {group.apps.map((a) => (
                            <span key={a.rp} className="admin-badge on">{a.label}</span>
                          ))}
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                      <Link href={`/admin/groups/detail?dn=${encodeURIComponent(group.dn)}`} className="admin-link">
                        Configure access →
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {data.pagination.totalPages > 1 && (
              <div className="admin-pagination">
                {data.pagination.page > 1 && (
                  <button onClick={() => go({ page: data.pagination.page - 1 })} className="admin-btn secondary">← Prev</button>
                )}
                <span className="page-info">
                  Page {data.pagination.page} of {data.pagination.totalPages} ({data.pagination.total} groups)
                </span>
                {data.pagination.page < data.pagination.totalPages && (
                  <button onClick={() => go({ page: data.pagination.page + 1 })} className="admin-btn secondary">Next →</button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
