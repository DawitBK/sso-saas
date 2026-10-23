'use client';

import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, Lock, LockOpen } from 'lucide-react';
import { ApiError, adminFetch } from '@shared/lib/adminApi';
import { EmptyState, ErrorState, PageSkeleton } from '@shared/ui/States';

interface Incident {
  sequence: string;
  occurredAt: string;
  kind: string;
  severity: 'info' | 'warning' | 'critical';
  actor: { userId?: string; maskedEmail?: string; ip?: string };
  operation: string;
  detail: Record<string, unknown>;
  response: { decision?: string; locked?: boolean; revoked?: boolean; mode?: string; note?: string; actorIsOwner?: boolean };
}

interface IncidentsData {
  items: Incident[];
  total: number;
  lock: { configured: boolean; locked: boolean; info: { at: string | null; reason: string | null; kind: string | null } | null; kind: 'file' | 'memory' | 'none'; responseMode: 'contain' | 'alert' | 'off' };
  chain: { valid: boolean; checked: number; brokenAt: string | null; problem: string | null };
  clearing: string;
}

const KIND_LABEL: Record<string, string> = {
  owner_op_denied: 'Owner-only operation refused',
  owner_op_without_sequence: 'Owner-only operation attempted outside the verification sequence',
  owner_verification_failed: 'Owner verification failed',
  owner_verification_locked: 'Owner verification locked',
  privilege_change_by_non_owner: 'Administrator rights changed (or attempted) by someone who is not the owner',
  audit_chain_broken: 'The audit log no longer verifies',
};

const SEVERITY_BADGE: Record<Incident['severity'], string> = { info: 'ui-badge-neutral', warning: 'ui-badge-warning', critical: 'ui-badge-danger' };
const MODE_LABEL = {
  contain: 'Contain automatically (record, alert, revoke the person, read-only)',
  alert: 'Alert only (record and alert; nothing is locked)',
  off: 'Off',
} as const;

const when = (iso: string) => new Date(iso).toLocaleString();

export default function SecurityIncidentsPage() {
  const query = useQuery({
    queryKey: ['admin-security-incidents'],
    queryFn: () => adminFetch<IncidentsData>('/api/v1/admin/security-incidents?limit=200'),
    staleTime: 0,
    refetchInterval: 30_000,
    retry: false,
  });

  if (query.isPending) return <PageSkeleton rows={2} />;
  if (query.isError) {
    if (query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 403)) {
      return (
        <>
          <div className="admin-page-header"><div><h1>Security incidents</h1></div></div>
          <div className="admin-card" role="note"><p className="admin-hint" style={{ margin: 0 }}>This page is the owner&apos;s alone.</p></div>
        </>
      );
    }
    return <ErrorState error={query.error} onRetry={() => query.refetch()} title="Security incidents could not be loaded" />;
  }

  const { items, total, lock, chain, clearing } = query.data;
  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Security incidents</h1>
          <p>What the platform noticed and what it did about it. The list is append-only and tamper-evident. This page only shows: nothing here can lift a lock.</p>
        </div>
      </div>

      <section className="admin-card" aria-labelledby="incident-lock-title" style={{ display: 'grid', gap: 8 }}>
        <h2 id="incident-lock-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {lock.locked ? <Lock size={18} aria-hidden="true" /> : <LockOpen size={18} aria-hidden="true" />} Containment
          <span className={`ui-badge ${lock.locked ? 'ui-badge-danger' : 'ui-badge-success'}`}>{lock.locked ? 'Read-only' : 'Normal'}</span>
        </h2>
        {lock.locked ? (
          <p role="alert" style={{ margin: 0 }}>
            SSO is read-only{lock.info?.at ? ` since ${when(lock.info.at)}` : ''}{lock.info?.reason ? `: ${lock.info.reason}` : ''}. Sign-in, sign-out, health and the licence pages still work. {clearing}
          </p>
        ) : (
          <p className="admin-hint" style={{ margin: 0 }}>
            No incident lock is in force.{lock.configured ? '' : ' (No lock file is configured on this server; a lock then lasts only until SSO restarts.)'}
          </p>
        )}
        <p className="admin-hint" style={{ margin: 0 }}>Automatic response: {MODE_LABEL[lock.responseMode]}.</p>
        <p className="admin-hint" style={{ margin: 0 }}>
          Incident log integrity:{' '}
          <span className={`ui-badge ${chain.valid ? 'ui-badge-success' : 'ui-badge-danger'}`}>{chain.valid ? `verified, ${chain.checked} row(s)` : `BROKEN at row ${chain.brokenAt}`}</span>
          {chain.problem ? ` (${chain.problem})` : ''}
        </p>
      </section>

      <section className="admin-card" aria-labelledby="incident-list-title">
        <h2 id="incident-list-title">Recorded incidents ({total})</h2>
        {items.length === 0 ? (
          <EmptyState title="No incidents recorded">Nothing has triggered the incident response on this server.</EmptyState>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="admin-table">
              <thead>
                <tr><th scope="col">#</th><th scope="col">When</th><th scope="col">What</th><th scope="col">Who</th><th scope="col">Response</th></tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={i.sequence}>
                    <td>{i.sequence}</td>
                    <td>{when(i.occurredAt)}</td>
                    <td>
                      <span className={`ui-badge ${SEVERITY_BADGE[i.severity]}`}><ShieldAlert size={12} aria-hidden="true" /> {i.severity}</span>{' '}
                      {KIND_LABEL[i.kind] ?? i.kind}
                      {i.operation ? <div className="admin-hint">{i.operation}</div> : null}
                    </td>
                    <td>{i.actor.maskedEmail ?? i.actor.userId ?? 'unknown'}{i.actor.ip ? <div className="admin-hint">{i.actor.ip}</div> : null}</td>
                    <td>
                      {i.response.decision ?? 'alert'}
                      {i.response.locked ? ' (locked)' : ''}{i.response.revoked ? ' (sessions revoked)' : ''}
                      {i.response.actorIsOwner ? <div className="admin-hint">the owner: never revoked or locked</div> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
