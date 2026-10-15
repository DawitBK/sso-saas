'use client';

import { Suspense, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { ArrowDown, ArrowUp, ArrowUpDown, Download, ShieldCheck, ShieldOff } from 'lucide-react';
import { apiPath } from '@shared/apiPath';
import { adminFetch, errorMessage, fetchCsrf } from '@shared/lib/adminApi';
import { formatDateTime, timeAgo } from '@shared/lib/format';
import { useConfirm } from '@shared/ui/Confirm';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';

interface User {
  id: string;
  email: string;
  given_name: string | null;
  family_name: string | null;
  group_count: number;
  is_active: boolean;
  source?: string | null;
  last_login_at: string | null;
  totp_enabled: boolean;
  must_change_password: boolean;
}

interface UsersData {
  users: User[];
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
  sort: { key: string; dir: 'asc' | 'desc' };
}

interface ResetRequest { id: string; userId: string; email: string; name: string; note: string; requestedAt: string }
interface ResetRequestsData { requests: ResetRequest[]; csrf: string }

interface ClientsData { clients: Array<{ clientId: string; name: string }> }
interface RoleCatalog { dmsRoles: string[]; gmsRoles: string[] }
interface BulkResult { action: string; results: Array<{ id: string; email: string | null; outcome: 'changed' | 'skipped' | 'refused'; message?: string }>; summary: { changed: number; skipped: number; refused: number; notFullyDark: number } }

type FilterKey = 'q' | 'client' | 'role' | 'status' | 'source' | 'mfa';
const FILTER_KEYS: FilterKey[] = ['q', 'client', 'role', 'status', 'source', 'mfa'];
type SortKey = 'email' | 'name' | 'status' | 'last_login';

export default function UsersPage() {
  return (
    <Suspense fallback={<PageSkeleton rows={2} />}>
      <UsersPageInner />
    </Suspense>
  );
}

function SortHeader({ label, sortKey, current, dir, onSort }: { label: string; sortKey: SortKey; current: string; dir: 'asc' | 'desc'; onSort: (k: SortKey) => void }) {
  const active = current === sortKey;
  const Icon = !active ? ArrowUpDown : dir === 'asc' ? ArrowUp : ArrowDown;
  return (
    <th aria-sort={active ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="ui-btn ui-btn-ghost ui-btn-sm" style={{ padding: 0, height: 'auto', textTransform: 'inherit', letterSpacing: 'inherit', fontWeight: 'inherit', color: 'inherit' }} onClick={() => onSort(sortKey)}>
        {label} <Icon size={12} aria-hidden="true" />
      </button>
    </th>
  );
}

/**
 * People who used "Forgot your password?" on the sign-in page. There is no email, so this is where it lands: reset the password on the person's
 * own page (which closes the request) and tell them the temporary one in person or by phone. Nothing is shown when nobody is waiting.
 */
function ResetRequestsCard() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [busyId, setBusyId] = useState<string | null>(null);
  const query = useQuery({
    queryKey: ['admin-reset-requests'],
    queryFn: () => adminFetch<ResetRequestsData>('/api/v1/admin/password-reset-requests'),
    staleTime: 0,
    refetchInterval: 60_000,
  });
  const requests = query.data?.requests ?? [];
  if (requests.length === 0) return null;

  async function dismiss(r: ResetRequest) {
    const sure = await confirm({
      title: `Dismiss the request from ${r.name || r.email}?`,
      message: <p>Use this for a duplicate, or someone who has remembered their password. Their password is not changed.</p>,
      confirmLabel: 'Dismiss request',
    });
    if (!sure) return;
    setBusyId(r.id);
    try {
      // A fresh token right before acting: the page's first load fires several requests at once and each may mint its own before the cookie exists, so the
      // token that came with the list can be one the cookie no longer matches. fetchCsrf() returns the token the cookie now holds.
      const csrf = await fetchCsrf();
      await adminFetch(`/api/v1/admin/password-reset-requests/${r.id}/dismiss`, { method: 'POST', body: { csrf } });
      toast.success('Request dismissed.');
      await queryClient.invalidateQueries({ queryKey: ['admin-reset-requests'] });
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="admin-card" style={{ marginBottom: 18, borderColor: 'var(--warning-border)' }} data-testid="reset-requests">
      <h2 className="admin-section-title" style={{ marginTop: 0 }}>
        {requests.length === 1 ? '1 person is waiting for a password reset' : `${requests.length} people are waiting for a password reset`}
      </h2>
      <p className="admin-hint">They asked on the sign-in page. Reset the password on their page (it closes the request), then tell them the temporary password in person or by phone.</p>
      <table className="admin-table">
        <thead>
          <tr><th>Person</th><th>What they said</th><th>Asked</th><th /></tr>
        </thead>
        <tbody>
          {requests.map((r) => (
            <tr key={r.id}>
              <td>
                <strong>{r.name || r.email}</strong>
                {r.name ? <div className="sub">{r.email}</div> : null}
              </td>
              <td style={{ color: 'var(--muted)' }}>{r.note || '—'}</td>
              <td title={formatDateTime(r.requestedAt)} style={{ whiteSpace: 'nowrap', color: 'var(--muted)' }}>{timeAgo(r.requestedAt)}</td>
              <td style={{ whiteSpace: 'nowrap', textAlign: 'right' }}>
                <Link href={`/admin/users/${r.userId}`} className="admin-btn">Reset password…</Link>{' '}
                <button type="button" className="admin-btn secondary" disabled={busyId === r.id} onClick={() => dismiss(r)}>Dismiss</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UsersPageInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const page = parseInt(searchParams.get('page') || '1');
  const pageSize = searchParams.get('pageSize') || '20';
  const sort = searchParams.get('sort') || 'email';
  const dir: 'asc' | 'desc' = searchParams.get('dir') === 'desc' ? 'desc' : 'asc';
  const current = {
    q: searchParams.get('q') || '',
    client: searchParams.get('client') || '',
    role: searchParams.get('role') || '',
    status: searchParams.get('status') || '',
    source: searchParams.get('source') || '',
    mfa: searchParams.get('mfa') || '',
  };
  // The search box is local until submitted; everything else applies as it is chosen.
  const [searchText, setSearchText] = useState(current.q);

  const queryFor = (overrides: Partial<Record<FilterKey | 'page' | 'pageSize' | 'sort' | 'dir', string>> = {}): string => {
    const merged: Record<string, string> = { ...current, page: String(page), pageSize, sort, dir, ...overrides };
    const query = new URLSearchParams();
    for (const key of FILTER_KEYS) if (merged[key]) query.set(key, merged[key]);
    if (merged.page && merged.page !== '1') query.set('page', merged.page);
    if (merged.pageSize && merged.pageSize !== '20') query.set('pageSize', merged.pageSize);
    if (merged.sort && merged.sort !== 'email') query.set('sort', merged.sort);
    if (merged.dir && merged.dir !== 'asc') query.set('dir', merged.dir);
    return query.toString();
  };

  const go = (overrides: Partial<Record<FilterKey | 'page' | 'pageSize' | 'sort' | 'dir', string>>) => {
    // Changing a filter, the sort or the page size returns to page 1; the selection belongs to the page it was made on.
    const reset = 'page' in overrides ? overrides : { ...overrides, page: '1' };
    setSelected(new Set());
    const qs = queryFor(reset);
    router.push(qs ? `/admin/users?${qs}` : '/admin/users');
  };

  const onSort = (key: SortKey) => go({ sort: key, dir: sort === key && dir === 'asc' ? 'desc' : 'asc' });

  // The two option lists the filters need. A failure here only costs the dropdown contents; the list itself still loads.
  const clients = useQuery({ queryKey: ['admin-clients-options'], queryFn: () => adminFetch<ClientsData>('/api/v1/admin/clients'), staleTime: 60_000, retry: 0 });
  const catalog = useQuery({ queryKey: ['admin-role-catalog'], queryFn: () => adminFetch<RoleCatalog>('/api/v1/admin/role-catalog'), staleTime: 60_000, retry: 0 });

  const listQs = queryFor();
  const list = useQuery({
    queryKey: ['admin-users', listQs],
    queryFn: () => adminFetch<UsersData>(`/api/v1/admin/users${listQs ? `?${listQs}` : ''}`),
    placeholderData: keepPreviousData,
    staleTime: 0,
  });

  const anyFilter = FILTER_KEYS.some((k) => current[k]);
  const users = useMemo(() => list.data?.users ?? [], [list.data]);
  const allOnPage = users.length > 0 && users.every((u) => selected.has(u.id));
  const exportHref = apiPath(`/api/v1/admin/users/export?${queryFor({ page: '1', pageSize: '20' })}`);

  function toggleAll() {
    setSelected(allOnPage ? new Set() : new Set(users.map((u) => u.id)));
  }
  function toggleOne(id: string) {
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function bulk(action: 'disable' | 'enable' | 'sign-out') {
    const ids = [...selected];
    const wording = {
      disable: { title: `Disable ${ids.length} ${ids.length === 1 ? 'person' : 'people'}?`, body: 'They are signed out of every system now and cannot sign in until they are enabled again. You cannot disable your own account.', label: 'Disable', danger: true },
      enable: { title: `Enable ${ids.length} ${ids.length === 1 ? 'person' : 'people'}?`, body: 'They can sign in again. Their access is whatever their groups give them.', label: 'Enable', danger: false },
      'sign-out': { title: `Sign ${ids.length} ${ids.length === 1 ? 'person' : 'people'} out everywhere?`, body: 'Every session and token they hold in SSO, DMS and GMS ends now. They can sign in again straight away.', label: 'Sign out', danger: true },
    }[action];
    const ok = await confirm({
      title: wording.title,
      message: <><p>{wording.body}</p><p>One audit entry is written for each person.</p></>,
      confirmLabel: wording.label,
      danger: wording.danger,
    });
    if (!ok) return;
    setBusy(true);
    try {
      const csrf = await fetchCsrf();
      const out = await adminFetch<BulkResult>('/api/v1/admin/users/bulk', { method: 'POST', body: { ids, action, csrf } });
      const { changed, skipped, refused, notFullyDark } = out.summary;
      const parts = [`${changed} changed`, skipped ? `${skipped} already so` : '', refused ? `${refused} refused` : ''].filter(Boolean);
      (refused ? toast.error : toast.success)(parts.join(', ') + (refused ? `: ${out.results.find((r) => r.outcome === 'refused')?.message ?? ''}` : '.'));
      if (notFullyDark > 0) toast(`${notFullyDark} of them may still hold a session in a system that could not be reached.`, { icon: '⚠️' });
      setSelected(new Set());
      await queryClient.invalidateQueries({ queryKey: ['admin-users'] });
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  const select = (label: string, key: FilterKey, options: Array<[string, string]>, anyLabel: string, children?: React.ReactNode) => (
    <label style={{ display: 'grid', gap: 4, fontSize: 12, color: 'var(--muted)' }}>
      {label}
      <select className="ui-input" value={current[key]} onChange={(e) => go({ [key]: e.target.value })} aria-label={`Filter by ${label.toLowerCase()}`}>
        <option value="">{anyLabel}</option>
        {options.map(([value, text]) => <option key={value} value={value}>{text}</option>)}
        {children}
      </select>
    </label>
  );

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Users</h1>
          <p>Every SSO account. Filter by who can reach a system, by the role they hold in it, or by two-factor; select people to act on several at once.</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <a href={exportHref} className="admin-btn secondary" download>
            <Download size={14} aria-hidden="true" /> Export CSV
          </a>
          <Link href="/admin/users/new" className="admin-btn">+ New user</Link>
        </div>
      </div>

      <ResetRequestsCard />

      <div className="admin-card">
        <form
          className="admin-search-bar"
          onSubmit={(e) => {
            e.preventDefault();
            go({ q: searchText.trim() });
          }}
        >
          <label htmlFor="user-search" className="admin-visually-hidden">Search by email</label>
          <input id="user-search" type="search" placeholder="Search by email" value={searchText} onChange={(e) => setSearchText(e.target.value)} className="ui-input" />
          <button className="admin-btn secondary" type="submit">Search</button>
        </form>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, margin: '12px 0 16px' }}>
          {select('Can sign in to', 'client', (clients.data?.clients ?? []).filter((c) => c.clientId !== 'portal').map((c) => [c.clientId, c.name || c.clientId]), 'Any application')}
          {select('Role', 'role', [['idp:admin', 'IdP Administrator']], 'Any role',
            <>
              {(catalog.data?.dmsRoles.length ?? 0) > 0 && (
                <optgroup label="DMS">{catalog.data?.dmsRoles.map((r) => <option key={`dms:${r}`} value={`dms:${r}`}>{r}</option>)}</optgroup>
              )}
              {(catalog.data?.gmsRoles.length ?? 0) > 0 && (
                <optgroup label="GMS">{catalog.data?.gmsRoles.map((r) => <option key={`gms:${r}`} value={`gms:${r}`}>{r}</option>)}</optgroup>
              )}
            </>)}
          {select('Status', 'status', [['active', 'Active'], ['inactive', 'Disabled']], 'Any status')}
          {select('Account type', 'source', [['local', 'Local'], ['ad', 'Active Directory']], 'Any type')}
          {select('Two-factor', 'mfa', [['enrolled', 'Enrolled'], ['not_enrolled', 'Not enrolled']], 'Any')}
          <label style={{ display: 'grid', gap: 4, fontSize: 12, color: 'var(--muted)' }}>
            Per page
            <select className="ui-input" value={pageSize} onChange={(e) => go({ pageSize: e.target.value })} aria-label="People per page">
              {['20', '50', '100'].map((n) => <option key={n} value={n}>{n}</option>)}
            </select>
          </label>
          {anyFilter && (
            <button type="button" className="admin-btn secondary" style={{ alignSelf: 'end' }} onClick={() => { setSearchText(''); setSelected(new Set()); router.push('/admin/users'); }}>
              Clear filters
            </button>
          )}
        </div>

        {selected.size > 0 && (
          <div className="health-banner" role="region" aria-label="Actions for the selected people" style={{ marginBottom: 14 }}>
            <strong>{selected.size} selected</strong>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginLeft: 'auto' }}>
              <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => bulk('sign-out')}>Sign out everywhere</button>
              <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => bulk('enable')}>Enable</button>
              <button type="button" className="admin-btn danger" disabled={busy} onClick={() => bulk('disable')}>Disable</button>
              <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => setSelected(new Set())}>Clear</button>
            </div>
          </div>
        )}

        {list.isPending ? (
          <PageSkeleton rows={1} />
        ) : list.isError ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} title="The list of people could not be loaded" />
        ) : users.length === 0 ? (
          <EmptyState title={anyFilter ? 'Nobody matches these filters' : 'There are no accounts yet'} action={anyFilter ? <button type="button" className="admin-btn secondary" onClick={() => { setSearchText(''); router.push('/admin/users'); }}>Clear filters</button> : <Link href="/admin/users/new" className="admin-btn">Create the first user</Link>}>
            {anyFilter ? 'Loosen a filter, or search for a different address.' : 'Accounts appear here once they are created or signed in through Active Directory.'}
          </EmptyState>
        ) : (
          <>
            <div style={{ overflowX: 'auto', opacity: list.isPlaceholderData ? 0.6 : 1 }}>
              <table className="admin-table">
                <thead>
                  <tr>
                    <th style={{ width: 32 }}>
                      <input type="checkbox" checked={allOnPage} onChange={toggleAll} aria-label="Select everyone on this page" />
                    </th>
                    <SortHeader label="Email" sortKey="email" current={sort} dir={dir} onSort={onSort} />
                    <SortHeader label="Name" sortKey="name" current={sort} dir={dir} onSort={onSort} />
                    <th>Type</th>
                    <th>Two-factor</th>
                    <th>Groups</th>
                    <SortHeader label="Status" sortKey="status" current={sort} dir={dir} onSort={onSort} />
                    <SortHeader label="Last sign-in" sortKey="last_login" current={sort} dir={dir} onSort={onSort} />
                    <th><span className="admin-visually-hidden">Open</span></th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.id} aria-selected={selected.has(user.id)}>
                      <td>
                        <input type="checkbox" checked={selected.has(user.id)} onChange={() => toggleOne(user.id)} aria-label={`Select ${user.email}`} />
                      </td>
                      <td>{user.email}</td>
                      <td>{[user.given_name, user.family_name].filter(Boolean).join(' ') || '—'}</td>
                      <td style={{ color: 'var(--muted)' }}>{user.source === 'ad' ? 'AD' : 'Local'}</td>
                      <td>
                        {user.totp_enabled ? (
                          <span className="ui-chip live"><ShieldCheck size={11} aria-hidden="true" /> Enrolled</span>
                        ) : (
                          <span className="ui-chip"><ShieldOff size={11} aria-hidden="true" /> None</span>
                        )}
                      </td>
                      <td>{user.group_count}</td>
                      <td>
                        <span className={`admin-badge ${user.is_active ? 'on' : 'off'}`}>{user.is_active ? 'Active' : 'Disabled'}</span>
                        {user.must_change_password ? <span className="ui-chip lock" style={{ marginLeft: 6 }}>Must change password</span> : null}
                      </td>
                      <td style={{ color: 'var(--muted)' }}>{user.last_login_at ? formatDateTime(user.last_login_at) : 'never'}</td>
                      <td>
                        <Link href={`/admin/users/${user.id}`} className="admin-link">Manage →</Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {list.data && list.data.pagination.totalPages > 1 && (
              <div className="admin-pagination">
                {list.data.pagination.page > 1 && (
                  <Link href={`/admin/users?${queryFor({ page: String(list.data.pagination.page - 1) })}`} className="admin-btn secondary">← Prev</Link>
                )}
                <span className="page-info">
                  Page {list.data.pagination.page} of {list.data.pagination.totalPages} ({list.data.pagination.total} people)
                </span>
                {list.data.pagination.page < list.data.pagination.totalPages && (
                  <Link href={`/admin/users?${queryFor({ page: String(list.data.pagination.page + 1) })}`} className="admin-btn secondary">Next →</Link>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}
