'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { adminFetch, errorMessage } from '@shared/lib/adminApi';
import { formatDateTime } from '@shared/lib/format';
import { useConfirm } from '@shared/ui/Confirm';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';

interface Session {
  id: string;
  kind: string;
  account_id: string | null;
  email: string | null;
  name: string | null;
  created_at: string;
  expires_at: string | null;
  /** Address and browser of the sign-in that created the session (from the Sign-ins record); null when no record matches. */
  ip: string | null;
  user_agent: string | null;
  /** The applications this single sign-on session has been used to open. */
  clients: string[];
}

interface SessionsData {
  sessions: Session[];
  csrf: string;
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}

const CLIENT_NAME: Record<string, string> = { edams: 'DMS', gms: 'GMS', portal: 'Portal' };

export default function SessionsPage() {
  return (
    <Suspense fallback={<PageSkeleton rows={2} />}>
      <SessionsPageInner />
    </Suspense>
  );
}

function SessionsPageInner() {
  const router = useRouter();
  const params = useSearchParams();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const page = Math.max(1, parseInt(params.get('page') || '1'));
  const q = params.get('q') || '';
  const [search, setSearch] = useState(q);

  const qs = (over: Record<string, string> = {}): string => {
    const merged: Record<string, string> = { q, page: String(page), ...over };
    const out = new URLSearchParams();
    if (merged.q) out.set('q', merged.q);
    if (merged.page && merged.page !== '1') out.set('page', merged.page);
    return out.toString();
  };
  const go = (over: Record<string, string>) => {
    const query = qs('page' in over ? over : { ...over, page: '1' });
    router.push(query ? `/admin/sessions?${query}` : '/admin/sessions');
  };

  const listQs = qs();
  const query = useQuery({
    queryKey: ['admin-sessions', listQs],
    queryFn: () => adminFetch<SessionsData>(`/api/v1/admin/sessions${listQs ? `?${listQs}` : ''}`),
    placeholderData: keepPreviousData,
    staleTime: 0,
  });

  const killSession = useMutation({
    mutationFn: (sessionId: string) =>
      adminFetch('/api/v1/admin/sessions/revoke', { method: 'POST', body: { session_id: sessionId, csrf: query.data?.csrf } }),
    onSuccess: () => {
      toast.success('Signed out everywhere');
      // Real invalidation instead of a manual local-state splice: the list (and any other view of live-session counts) refetches.
      void queryClient.invalidateQueries({ queryKey: ['admin-sessions'] });
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  // POST /api/v1/admin/sessions/revoke is account-wide, not per-session: tokens and grants are only ever tracked per account, never
  // per session. An administrator killing what looks like one stale desktop session also signs that person out of DMS, GMS and the
  // portal on every device, so the confirmation says exactly that.
  async function handleKill(s: Session) {
    const ok = await confirm({
      title: `Sign ${s.email ?? 'this person'} out everywhere?`,
      message: (
        <>
          <p>This ends the whole account, not only the row you clicked: every single sign-on session, access and refresh token, grant and the GMS bridge session, on every device.</p>
          <p>They can sign in again straight away. One audit entry is written.</p>
        </>
      ),
      confirmLabel: 'Sign out everywhere',
      danger: true,
    });
    if (ok) killSession.mutate(s.id);
  }

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Active Sessions</h1>
          <p>
            Live single sign-on sessions, with the applications each has opened. Signing out ends the whole account, every session, token and grant on every device. Portal-only
            sessions are not listed here. The address is the one the person signed in from, read from the Sign-ins record; it shows — when no record matches.
          </p>
        </div>
      </div>

      <div className="admin-card">
        <form className="admin-search-bar" onSubmit={(e) => { e.preventDefault(); go({ q: search.trim() }); }}>
          <label htmlFor="session-search" className="admin-visually-hidden">Search by email or name</label>
          <input id="session-search" type="search" className="ui-input" placeholder="Search by email or name" value={search} onChange={(e) => setSearch(e.target.value)} />
          <button className="admin-btn secondary" type="submit">Search</button>
          {q ? <button type="button" className="admin-btn secondary" onClick={() => { setSearch(''); router.push('/admin/sessions'); }}>Clear</button> : null}
        </form>

        {query.isPending ? (
          <PageSkeleton rows={1} />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => query.refetch()} title="The sessions could not be loaded" />
        ) : query.data.sessions.length === 0 ? (
          <EmptyState title={q ? 'No sessions match that search' : 'Nobody is signed in right now'}>
            {q ? 'Try a different name or address.' : 'Live single sign-on sessions appear here while people are signed in.'}
          </EmptyState>
        ) : (
          <>
            <div style={{ overflowX: 'auto', opacity: query.isPlaceholderData ? 0.6 : 1 }}>
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Email</th>
                    <th>Account ID</th>
                    <th>Opened</th>
                    <th title="Applications this session has been used to open">Applications</th>
                    <th title="Address of the sign-in that created this session, taken from the Sign-ins record">IP address</th>
                    <th>Expires</th>
                    <th><span className="admin-visually-hidden">Action</span></th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.sessions.map((session) => (
                    <tr key={session.id}>
                      <td>
                        {session.email || '—'}
                        {session.name ? <div style={{ color: 'var(--muted)', fontSize: 12 }}>{session.name}</div> : null}
                      </td>
                      <td><code className="admin-code">{session.account_id || '—'}</code></td>
                      <td style={{ color: 'var(--muted)', fontSize: '12px' }}>{formatDateTime(session.created_at)}</td>
                      <td>
                        {session.clients.length === 0 ? (
                          <span style={{ color: 'var(--muted)', fontSize: 12 }}>none yet</span>
                        ) : (
                          <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
                            {session.clients.map((c) => <span key={c} className="ui-chip">{CLIENT_NAME[c] ?? c}</span>)}
                          </span>
                        )}
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px' }} title={session.user_agent || undefined}>{session.ip || '—'}</td>
                      <td style={{ color: 'var(--muted)', fontSize: '12px' }}>{session.expires_at ? formatDateTime(session.expires_at) : 'Never'}</td>
                      <td>
                        <button type="button" onClick={() => void handleKill(session)} disabled={killSession.isPending} className="admin-btn danger">
                          Sign out everywhere
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {query.data.pagination.totalPages > 1 && (
              <div className="admin-pagination">
                {query.data.pagination.page > 1 && (
                  <button type="button" onClick={() => go({ page: String(query.data.pagination.page - 1) })} className="admin-btn secondary">← Prev</button>
                )}
                <span className="page-info">
                  Page {query.data.pagination.page} of {query.data.pagination.totalPages} ({query.data.pagination.total} sessions)
                </span>
                {query.data.pagination.page < query.data.pagination.totalPages && (
                  <button type="button" onClick={() => go({ page: String(query.data.pagination.page + 1) })} className="admin-btn secondary">Next →</button>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
