'use client';

import { Fragment, Suspense, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { ChevronDown, ChevronRight, Download, ShieldCheck } from 'lucide-react';
import { apiPath } from '@shared/apiPath';
import { adminFetch, errorMessage } from '@shared/lib/adminApi';
import { auditActionLabel, auditFamily, auditFamilyLabel } from '@shared/lib/auditLabels';
import { formatDateTime } from '@shared/lib/format';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';
import { Modal } from '@shared/ui/Modal';

interface AuditEntry {
  id: string;
  sequence_number: string;
  created_at: string;
  actor_email: string;
  action: string;
  target: string;
  detail: Record<string, unknown> | null;
  ip: string | null;
}

interface AuditData {
  entries: AuditEntry[];
  actions: string[];
  filters: { q: string; action: string; actor: string; from: string; to: string };
  pagination: { page: number; pageSize: number; total: number; totalPages: number };
}

/** Mirrors ChainBreak in backend/src/admin/audit.ts (without its server-side pin). */
interface ChainBreak {
  sequenceNumber: string;
  kind: 'hash' | 'linkage' | 'ordering' | 'head' | 'tail' | 'empty';
  message: string;
  acknowledgeable: boolean;
  acknowledged?: { by: string; at: string; reason: string };
}

/** Mirrors ChainVerification in backend/src/admin/audit.ts. */
interface ChainVerification {
  valid: boolean;
  checked: number;
  fromSequence?: string;
  toSequence?: string;
  legacyCount: number;
  brokenAtSequence?: string;
  breaks: ChainBreak[];
  openBreaks: number;
  acknowledgedBreaks: number;
  truncated: boolean;
  message: string;
}

const BREAK_LABEL: Record<ChainBreak['kind'], string> = {
  hash: 'An entry was edited',
  linkage: 'An entry is missing or was inserted',
  ordering: 'Entries were renumbered or reordered',
  head: 'The start of the log was deleted',
  tail: 'The end of the log was deleted or the last entry edited',
  empty: 'The whole log was deleted',
};

type Key = 'q' | 'action' | 'actor' | 'from' | 'to';
const KEYS: Key[] = ['q', 'action', 'actor', 'from', 'to'];

export default function AuditPage() {
  return (
    <Suspense fallback={<PageSkeleton rows={2} />}>
      <AuditPageInner />
    </Suspense>
  );
}

function AuditPageInner() {
  const router = useRouter();
  const params = useSearchParams();
  const page = Math.max(1, parseInt(params.get('page') || '1'));
  const current: Record<Key, string> = { q: params.get('q') || '', action: params.get('action') || '', actor: params.get('actor') || '', from: params.get('from') || '', to: params.get('to') || '' };
  const [draft, setDraft] = useState(current);
  const [open, setOpen] = useState<Set<string>>(new Set());
  // Every row carries an HMAC over the previous row's hash, so the trail is tamper-evident, but only if somebody recomputes the
  // chain. Deliberately on demand: it walks every row, which is not something to do on every visit.
  const [chain, setChain] = useState<ChainVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  // Only the platform administrator may acknowledge a known break (the server enforces it; the button is simply not offered to anyone else).
  const [canAcknowledge, setCanAcknowledge] = useState(false);
  const [minReason, setMinReason] = useState(20);
  const [csrf, setCsrf] = useState('');
  const [acking, setAcking] = useState<ChainBreak | null>(null);
  const [reason, setReason] = useState('');
  const [ackBusy, setAckBusy] = useState(false);
  const [ackError, setAckError] = useState('');

  const qs = (over: Partial<Record<Key | 'page', string>> = {}): string => {
    const merged: Record<string, string> = { ...current, page: String(page), ...over };
    const out = new URLSearchParams();
    for (const k of KEYS) if (merged[k]) out.set(k, merged[k]);
    if (merged.page && merged.page !== '1') out.set('page', merged.page);
    return out.toString();
  };
  const go = (over: Partial<Record<Key | 'page', string>>) => {
    const query = qs('page' in over ? over : { ...over, page: '1' });
    router.push(query ? `/admin/audit?${query}` : '/admin/audit');
  };

  const listQs = qs();
  const query = useQuery({
    queryKey: ['admin-audit', listQs],
    queryFn: () => adminFetch<AuditData>(`/api/v1/admin/audit?limit=50${listQs ? `&${listQs}` : ''}`),
    placeholderData: keepPreviousData,
    staleTime: 0,
  });

  async function verifyChain() {
    setVerifying(true);
    try {
      const out = await adminFetch<{ chain: ChainVerification; viewerIsPlatformAdmin: boolean; minReasonLength: number; csrf: string }>('/api/v1/admin/audit/verify');
      setChain(out.chain);
      setCanAcknowledge(out.viewerIsPlatformAdmin);
      setMinReason(out.minReasonLength);
      setCsrf(out.csrf);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setVerifying(false);
    }
  }

  async function acknowledge() {
    if (!acking) return;
    setAckBusy(true);
    setAckError('');
    try {
      const out = await adminFetch<{ chain: ChainVerification; csrf: string }>('/api/v1/admin/audit/chain-acknowledgements', {
        method: 'POST',
        body: { sequenceNumber: acking.sequenceNumber, kind: acking.kind, reason, csrf },
      });
      setChain(out.chain);
      setCsrf(out.csrf);
      setAcking(null);
      setReason('');
      toast.success('Recorded. The break stays listed, marked as acknowledged.');
      void query.refetch();
    } catch (err) {
      setAckError(errorMessage(err));
    } finally {
      setAckBusy(false);
    }
  }

  const families = useMemo(() => {
    const byFamily = new Map<string, string[]>();
    for (const a of query.data?.actions ?? []) byFamily.set(auditFamily(a), [...(byFamily.get(auditFamily(a)) ?? []), a]);
    return [...byFamily.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [query.data?.actions]);

  const anyFilter = KEYS.some((k) => current[k]);
  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Audit Log</h1>
          <p>Every administrative action, most recent first. Search it, narrow it by action, person or date, and export what you see.</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <a className="admin-btn secondary" href={apiPath(`/api/v1/admin/audit/export${listQs ? `?${listQs}` : ''}`)} download>
            <Download size={14} aria-hidden="true" /> Export CSV
          </a>
          <button type="button" className="admin-btn secondary" disabled={verifying} onClick={verifyChain}>
            <ShieldCheck size={14} aria-hidden="true" /> {verifying ? 'Verifying…' : 'Verify integrity'}
          </button>
        </div>
      </div>

      {chain && (
        <div
          className="admin-card"
          role="status"
          style={{
            marginBottom: '18px',
            background: chain.valid ? 'var(--success-bg)' : 'var(--danger-bg, var(--warning-bg))',
            borderColor: chain.valid ? 'var(--success-border)' : 'var(--warning-border)',
            color: chain.valid ? 'var(--success-text)' : 'var(--warning-text)',
          }}
        >
          <strong>{chain.valid ? 'Chain intact' : 'CHAIN BROKEN'}</strong> — {chain.message}
          <p className="admin-hint" style={{ color: 'inherit', opacity: 0.85 }}>
            {chain.checked} {chain.checked === 1 ? 'entry' : 'entries'} recomputed
            {chain.fromSequence && chain.toSequence ? ` (sequence ${chain.fromSequence}–${chain.toSequence})` : ''}
            {chain.legacyCount > 0 ? ` · ${chain.legacyCount} pre-date the hash chain and cannot be verified` : ''}
            {chain.openBreaks > 0 ? ` · ${chain.openBreaks} unexplained` : ''}
            {chain.acknowledgedBreaks > 0 ? ` · ${chain.acknowledgedBreaks} acknowledged` : ''}
          </p>
        </div>
      )}

      {chain && chain.breaks.length > 0 && (
        <div className="admin-card" style={{ marginBottom: '18px' }}>
          <h2 className="admin-section-title" style={{ marginTop: 0 }}>Problems found in the chain</h2>
          <p className="admin-hint">
            Each one is a place where the log no longer matches its own fingerprints. An old, explained one can be acknowledged by the platform
            administrator; it stays listed, and the acknowledgement becomes an entry in this log. A row changed again after that counts as a new problem.
            {chain.truncated ? ' More problems exist than are listed here.' : ''}
          </p>
          <table className="admin-table" data-testid="chain-breaks">
            <thead>
              <tr><th>Entry</th><th>What happened</th><th>Status</th><th /></tr>
            </thead>
            <tbody>
              {chain.breaks.map((b) => (
                <tr key={`${b.sequenceNumber}-${b.kind}`}>
                  <td style={{ whiteSpace: 'nowrap' }}>#{b.sequenceNumber}</td>
                  <td>
                    <strong>{BREAK_LABEL[b.kind]}</strong>
                    <div className="sub">{b.message}</div>
                  </td>
                  <td>
                    {b.acknowledged ? (
                      <>
                        <span className="admin-badge on">Acknowledged</span>
                        <div className="sub">{b.acknowledged.by === 'platform' ? 'Platform administrator' : b.acknowledged.by}, {formatDateTime(b.acknowledged.at)}</div>
                        <div className="sub">{b.acknowledged.reason}</div>
                      </>
                    ) : (
                      <span className="admin-badge off">Unexplained</span>
                    )}
                  </td>
                  <td>
                    {!b.acknowledged && b.acknowledgeable && canAcknowledge ? (
                      <button type="button" className="admin-btn secondary" onClick={() => { setAcking(b); setReason(''); setAckError(''); }}>Acknowledge…</button>
                    ) : !b.acknowledged && !b.acknowledgeable ? (
                      <span className="sub">Cannot be acknowledged: restore from a backup</span>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        open={acking !== null}
        title={acking ? `Acknowledge the problem at entry #${acking.sequenceNumber}?` : ''}
        onClose={() => setAcking(null)}
        dismissible={!ackBusy}
        width={560}
        footer={
          <>
            <button type="button" className="admin-btn secondary" onClick={() => setAcking(null)} disabled={ackBusy}>Cancel</button>
            <button type="button" className="admin-btn danger" onClick={acknowledge} disabled={ackBusy || reason.trim().length < minReason}>{ackBusy ? 'Recording…' : 'Acknowledge this problem'}</button>
          </>
        }
      >
        <p className="ui-modal-text">
          You are stating that you know why this entry no longer matches and that it is harmless (for example, a restore from an older backup). Nothing is
          changed or hidden: the problem stays listed, and your name and reason are added to this log as an entry. If this entry is altered again, it becomes a new
          unexplained problem.
        </p>
        <label className="ui-field" style={{ marginTop: 12 }}>
          <span className="sub">Why is it known and harmless? (at least {minReason} characters)</span>
          <textarea className="ui-input" rows={4} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} data-autofocus />
        </label>
        {ackError ? <p className="ui-field-error" role="alert">{ackError}</p> : null}
      </Modal>

      <div className="admin-card">
        <form
          className="admin-search-bar"
          style={{ alignItems: 'flex-end' }}
          onSubmit={(e) => { e.preventDefault(); go({ ...draft }); }}
        >
          <label className="ui-field" style={{ flex: '2 1 220px' }}>
            <span className="sub">Search</span>
            <input className="ui-input" placeholder="Person, target or action" value={draft.q} onChange={(e) => setDraft({ ...draft, q: e.target.value })} />
          </label>
          <label className="ui-field" style={{ flex: '1 1 200px' }}>
            <span className="sub">What was done</span>
            <select className="ui-input" value={draft.action} onChange={(e) => setDraft({ ...draft, action: e.target.value })}>
              <option value="">Anything</option>
              {families.map(([family, actions]) => (
                <optgroup key={family} label={auditFamilyLabel(family)}>
                  <option value={`${family}.`}>All {auditFamilyLabel(family).toLowerCase()}</option>
                  {actions.map((a) => <option key={a} value={a}>{auditActionLabel(a)}</option>)}
                </optgroup>
              ))}
            </select>
          </label>
          <label className="ui-field" style={{ flex: '1 1 180px' }}>
            <span className="sub">Done by</span>
            <input className="ui-input" placeholder="Email, or “platform”" value={draft.actor} onChange={(e) => setDraft({ ...draft, actor: e.target.value })} />
          </label>
          <label className="ui-field">
            <span className="sub">From</span>
            <input className="ui-input" type="date" value={draft.from} onChange={(e) => setDraft({ ...draft, from: e.target.value })} />
          </label>
          <label className="ui-field">
            <span className="sub">To</span>
            <input className="ui-input" type="date" value={draft.to} onChange={(e) => setDraft({ ...draft, to: e.target.value })} />
          </label>
          <button className="admin-btn" type="submit">Apply</button>
          {anyFilter ? <button type="button" className="admin-btn secondary" onClick={() => { setDraft({ q: '', action: '', actor: '', from: '', to: '' }); router.push('/admin/audit'); }}>Clear</button> : null}
        </form>

        {query.isPending ? (
          <PageSkeleton rows={1} />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => query.refetch()} title="The audit log could not be loaded" />
        ) : query.data.entries.length === 0 ? (
          <EmptyState title={anyFilter ? 'Nothing matches these filters' : 'No audit entries yet'}>
            {anyFilter ? 'Loosen a filter or widen the dates.' : 'Administrative actions are recorded here as they happen.'}
          </EmptyState>
        ) : (
          <>
            <div style={{ overflowX: 'auto', opacity: query.isPlaceholderData ? 0.6 : 1 }}>
              <table className="admin-table">
                <thead>
                  <tr>
                    <th style={{ width: 28 }}><span className="admin-visually-hidden">Details</span></th>
                    <th>When</th>
                    <th>Who</th>
                    <th>What</th>
                    <th>Target</th>
                    <th>Address</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.entries.map((entry) => {
                    const expanded = open.has(entry.id);
                    const hasDetail = entry.detail && Object.keys(entry.detail).length > 0;
                    return (
                      <Fragment key={entry.id}>
                        <tr aria-expanded={hasDetail ? expanded : undefined}>
                          <td>
                            {hasDetail ? (
                              <button type="button" className="ui-btn ui-btn-ghost ui-btn-icon ui-btn-sm" aria-expanded={expanded} aria-label={`${expanded ? 'Hide' : 'Show'} details of entry ${entry.sequence_number}`} onClick={() => toggle(entry.id)}>
                                {expanded ? <ChevronDown aria-hidden="true" /> : <ChevronRight aria-hidden="true" />}
                              </button>
                            ) : null}
                          </td>
                          <td style={{ color: 'var(--muted)', fontSize: 12, whiteSpace: 'nowrap' }}>{formatDateTime(entry.created_at)}</td>
                          <td>{entry.actor_email === 'platform' ? <span className="ui-chip lock">Platform administrator</span> : entry.actor_email}</td>
                          <td>
                            {auditActionLabel(entry.action)}
                            <div><code className="admin-code" style={{ fontSize: 11 }}>{entry.action}</code></div>
                          </td>
                          <td style={{ fontSize: 12 }}>{entry.target || '—'}</td>
                          <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{entry.ip || '—'}</td>
                        </tr>
                        {expanded && hasDetail ? (
                          <tr>
                            <td />
                            <td colSpan={5}>
                              <pre className="admin-code" style={{ margin: 0, padding: 12, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-word', borderRadius: 8 }}>
                                {JSON.stringify(entry.detail, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {query.data.pagination.totalPages > 1 && (
              <div className="admin-pagination">
                {query.data.pagination.page > 1 && (
                  <button type="button" onClick={() => go({ page: String(query.data.pagination.page - 1) })} className="admin-btn secondary">← Prev</button>
                )}
                <span className="page-info">
                  Page {query.data.pagination.page} of {query.data.pagination.totalPages} ({query.data.pagination.total} entries)
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
