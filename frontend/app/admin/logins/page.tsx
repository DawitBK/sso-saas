'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Download } from 'lucide-react';
import { apiPath } from '@shared/apiPath';
import { adminFetch } from '@shared/lib/adminApi';
import { formatDateTime } from '@shared/lib/format';
import { isNotableSuccess, loginReasonLabel } from '@shared/lib/loginReasons';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';

interface LoginAttempt {
  id: string;
  email: string;
  /** The account's real id from the user table; absent when the address matches no account. */
  account_id?: string | null;
  success: boolean;
  reason: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
}

interface LoginsData {
  logins: LoginAttempt[];
  reasons: string[];
  /** How long the server keeps sign-in records (the purge job's retention). */
  retentionDays?: number;
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}

type Key = 'filter' | 'q' | 'reason' | 'from' | 'to';
const KEYS: Key[] = ['filter', 'q', 'reason', 'from', 'to'];

export default function LoginsPage() {
  return (
    <Suspense fallback={<PageSkeleton rows={2} />}>
      <LoginsPageInner />
    </Suspense>
  );
}

function LoginsPageInner() {
  const router = useRouter();
  const params = useSearchParams();
  const page = Math.max(1, parseInt(params.get('page') || '1'));
  const current: Record<Key, string> = { filter: params.get('filter') || '', q: params.get('q') || '', reason: params.get('reason') || '', from: params.get('from') || '', to: params.get('to') || '' };
  const [search, setSearch] = useState(current.q);

  const qs = (over: Partial<Record<Key | 'page', string>> = {}): string => {
    const merged: Record<string, string> = { ...current, page: String(page), ...over };
    const out = new URLSearchParams();
    for (const k of KEYS) if (merged[k]) out.set(k, merged[k]);
    if (merged.page && merged.page !== '1') out.set('page', merged.page);
    return out.toString();
  };
  const go = (over: Partial<Record<Key | 'page', string>>) => {
    const query = qs('page' in over ? over : { ...over, page: '1' });
    router.push(query ? `/admin/logins?${query}` : '/admin/logins');
  };

  const listQs = qs();
  const query = useQuery({
    queryKey: ['admin-logins', listQs],
    queryFn: () => adminFetch<LoginsData>(`/api/v1/admin/logins${listQs ? `?${listQs}` : ''}`),
    placeholderData: keepPreviousData,
    staleTime: 0,
  });
  const anyFilter = KEYS.some((k) => current[k]);
  const result = current.filter === 'success' || current.filter === 'failed' ? current.filter : 'all';

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Sign-in History</h1>
          <p>
            Authentication attempts, newest first. Records are kept for {query.data?.retentionDays ?? 90} days and then deleted; narrow the list by
            result, person or address, reason and date (server time, both days included).
          </p>
        </div>
        <a className="admin-btn secondary" href={apiPath(`/api/v1/admin/logins/export${listQs ? `?${listQs}` : ''}`)} download>
          <Download size={14} aria-hidden="true" /> Export CSV
        </a>
      </div>

      <div className="admin-card">
        <div role="group" aria-label="Result" style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
          {([['all', 'All'], ['success', 'Success'], ['failed', 'Failed']] as const).map(([value, label]) => (
            <button key={value} type="button" aria-pressed={result === value} className={`admin-btn ${result === value ? '' : 'secondary'}`} onClick={() => go({ filter: value === 'all' ? '' : value })}>
              {label}
            </button>
          ))}
        </div>
        <form className="admin-search-bar" style={{ alignItems: 'flex-end' }} onSubmit={(e) => { e.preventDefault(); go({ q: search.trim() }); }}>
          <label className="ui-field" style={{ flex: '2 1 220px' }}>
            <span className="sub">Email or address</span>
            <input className="ui-input" placeholder="person@example.com or 10.0.0.5" value={search} onChange={(e) => setSearch(e.target.value)} />
          </label>
          <label className="ui-field" style={{ flex: '1 1 220px' }}>
            <span className="sub">Reason</span>
            <select className="ui-input" value={current.reason} onChange={(e) => go({ reason: e.target.value })}>
              <option value="">Any</option>
              {(query.data?.reasons ?? []).map((r) => <option key={r} value={r}>{loginReasonLabel(false, r)}</option>)}
            </select>
          </label>
          <label className="ui-field">
            <span className="sub">From</span>
            <input className="ui-input" type="date" value={current.from} max={current.to || undefined} onChange={(e) => go({ from: e.target.value })} />
          </label>
          <label className="ui-field">
            <span className="sub">To</span>
            <input className="ui-input" type="date" value={current.to} min={current.from || undefined} onChange={(e) => go({ to: e.target.value })} />
          </label>
          <button className="admin-btn secondary" type="submit">Search</button>
          {anyFilter ? <button type="button" className="admin-btn secondary" onClick={() => { setSearch(''); router.push('/admin/logins'); }}>Clear</button> : null}
        </form>

        {query.isPending ? (
          <PageSkeleton rows={1} />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => query.refetch()} title="The sign-in history could not be loaded" />
        ) : query.data.logins.length === 0 ? (
          <EmptyState title={anyFilter ? 'No attempts match these filters' : 'No sign-in attempts recorded yet'}>
            {anyFilter ? 'Loosen a filter or widen the dates.' : 'Every attempt, successful or not, is listed here.'}
          </EmptyState>
        ) : (
          <>
            <div style={{ overflowX: 'auto', opacity: query.isPlaceholderData ? 0.6 : 1 }}>
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Email</th>
                    <th>Account ID</th>
                    <th>Result</th>
                    <th>IP address</th>
                    <th>Browser</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.logins.map((attempt) => (
                    <tr key={attempt.id}>
                      <td style={{ color: 'var(--muted)', fontSize: '12px', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>{formatDateTime(attempt.created_at)}</td>
                      <td>{attempt.email}</td>
                      <td><code className="admin-code">{attempt.account_id || '—'}</code></td>
                      <td>
                        <span className={`admin-badge ${attempt.success ? 'on' : 'off'}`}>{attempt.success ? 'Success' : 'Failed'}</span>
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{attempt.ip || '—'}</td>
                      <td style={{ fontSize: '12px', color: 'var(--muted)', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={attempt.user_agent || undefined}>
                        {attempt.user_agent || '—'}
                      </td>
                      <td style={{ fontSize: '12px', color: isNotableSuccess(attempt.success, attempt.reason) ? 'var(--warning-text)' : 'var(--muted)' }} title={attempt.reason || undefined}>
                        {attempt.reason ? loginReasonLabel(attempt.success, attempt.reason) : '—'}
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
                  Page {query.data.pagination.page} of {query.data.pagination.totalPages} ({query.data.pagination.total} attempts)
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
