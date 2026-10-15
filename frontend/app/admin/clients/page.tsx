'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { AlertTriangle, Copy, KeyRound, Lock, Pencil, Power, RotateCcw, Users } from 'lucide-react';
import { adminFetch, errorMessage } from '@shared/lib/adminApi';
import { formatDateTime, timeAgo } from '@shared/lib/format';
import { useConfirm } from '@shared/ui/Confirm';
import { Modal } from '@shared/ui/Modal';
import { ErrorState, PageSkeleton } from '@shared/ui/States';

interface Client {
  clientId: string;
  name: string;
  active: boolean;
  scopes: string[];
  grantTypes: string[];
  authMethod: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  urisDrift: boolean;
  secretIsDevDefault: boolean;
  secretRotatedAt: string | null;
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
  pattern: string;
  rolesScope: string | null;
  critical: string | null;
  secretNote: string | null;
  usage: { activeGrants: number; activeRefreshTokens: number; activeAccessTokens: number; lastTokenIssuedAt: string | null };
  entitledUsers: number | null;
}
interface ClientsData { clients: Client[]; viewerIsPlatformAdmin: boolean; protectedClients: string[]; csrf: string }

function CopyButton({ text, label }: { text: string; label: string }) {
  return (
    <button
      type="button"
      className="ui-btn ui-btn-ghost ui-btn-icon ui-btn-sm"
      aria-label={label}
      title={label}
      onClick={() => navigator.clipboard.writeText(text).then(() => toast.success('Copied'), () => toast.error('Could not copy'))}
    >
      <Copy aria-hidden="true" />
    </button>
  );
}

function UriList({ title, uris, empty }: { title: string; uris: string[]; empty: string }) {
  return (
    <div>
      <div className="sub" style={{ margin: '0 0 6px', fontWeight: 600 }}>{title}</div>
      {uris.length === 0 ? (
        <p className="admin-hint" style={{ margin: 0 }}>{empty}</p>
      ) : (
        <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 4 }}>
          {uris.map((u) => (
            <li key={u} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <code className="admin-code" style={{ fontSize: 12, wordBreak: 'break-all' }}>{u}</code>
              <CopyButton text={u} label={`Copy ${u}`} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function secretAge(c: Client): string {
  if (c.secretRotatedAt) return `Rotated ${timeAgo(c.secretRotatedAt)} (${formatDateTime(c.secretRotatedAt)})`;
  return `Never rotated from the console; in place since ${formatDateTime(c.createdAt)}`;
}

export default function ClientsPage() {
  const queryClient = useQueryClient();
  const confirm = useConfirm();
  const query = useQuery({ queryKey: ['admin-clients'], queryFn: () => adminFetch<ClientsData>('/api/v1/admin/clients'), staleTime: 0 });
  const [csrf, setCsrf] = useState('');
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<Client | null>(null);
  const [redirectText, setRedirectText] = useState('');
  const [logoutText, setLogoutText] = useState('');
  const [editError, setEditError] = useState<string | null>(null);
  const [rotating, setRotating] = useState<Client | null>(null);
  const [rotateConfirm, setRotateConfirm] = useState('');
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<{ client: Client; secret: string } | null>(null);
  const [saved, setSaved] = useState(false);

  const token = csrf || query.data?.csrf || '';

  async function act<T extends { csrf: string }>(path: string, method: 'PUT' | 'POST', body: Record<string, unknown>): Promise<T> {
    setBusy(true);
    try {
      const out = await adminFetch<T>(path, { method, body: { ...body, csrf: token } });
      setCsrf(out.csrf);
      await queryClient.invalidateQueries({ queryKey: ['admin-clients'] });
      return out;
    } finally {
      setBusy(false);
    }
  }

  function openEdit(c: Client) {
    setEditing(c);
    setRedirectText(c.redirectUris.join('\n'));
    setLogoutText(c.postLogoutRedirectUris.join('\n'));
    setEditError(null);
  }

  async function saveEdit() {
    if (!editing) return;
    const lines = (t: string) => t.split('\n').map((l) => l.trim()).filter(Boolean);
    try {
      await act(`/api/v1/admin/clients/${editing.clientId}/uris`, 'PUT', { redirectUris: lines(redirectText), postLogoutRedirectUris: lines(logoutText) });
      toast.success(`${editing.name}: addresses saved. They apply to the next sign-in.`);
      setEditing(null);
    } catch (err) {
      setEditError(errorMessage(err));
    }
  }

  async function restore(c: Client) {
    const ok = await confirm({
      title: `Restore the configured addresses for ${c.name}?`,
      message: <p>The redirect and sign-out addresses go back to what the server&apos;s configuration says, replacing what is stored now. The change is written to the audit log.</p>,
      confirmLabel: 'Restore',
    });
    if (!ok) return;
    try {
      await act(`/api/v1/admin/clients/${c.clientId}/restore-uris`, 'POST', {});
      toast.success('Configured addresses restored');
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function toggle(c: Client) {
    const turningOff = c.active;
    const ok = await confirm({
      title: turningOff ? `Switch off ${c.name}?` : `Switch ${c.name} back on?`,
      message: turningOff ? (
        <>
          <p>Nobody will be able to sign in to <strong>{c.name}</strong> through SSO, and everything it already holds ends now: its sign-in grants and tokens are deleted ({c.usage.activeGrants} grant{c.usage.activeGrants === 1 ? '' : 's'}, {c.usage.activeRefreshTokens} renewable session{c.usage.activeRefreshTokens === 1 ? '' : 's'}).</p>
          <p>People already inside the application stay signed in there until its own session ends. Switching back on restores sign-in; the ended sessions are not restored.</p>
        </>
      ) : (
        <p>Sign-in to <strong>{c.name}</strong> through SSO works again straight away.</p>
      ),
      confirmLabel: turningOff ? 'Switch off' : 'Switch on',
      danger: turningOff,
      requireText: turningOff ? c.clientId : undefined,
    });
    if (!ok) return;
    try {
      const out = await act<{ csrf: string; revokedArtifacts?: number }>(`/api/v1/admin/clients/${c.clientId}/active`, 'PUT', { active: !c.active });
      toast.success(turningOff ? `${c.name} is off (${out.revokedArtifacts ?? 0} tokens and grants ended)` : `${c.name} is on`);
    } catch (err) {
      toast.error(errorMessage(err));
    }
  }

  async function rotate() {
    if (!rotating) return;
    try {
      const out = await act<{ csrf: string; secret: string }>(`/api/v1/admin/clients/${rotating.clientId}/rotate-secret`, 'POST', { confirm: rotateConfirm });
      setRevealed({ client: rotating, secret: out.secret });
      setSaved(false);
      setRotating(null);
      setRotateConfirm('');
    } catch (err) {
      setRotateError(errorMessage(err));
    }
  }

  if (query.isPending) return <PageSkeleton rows={3} />;
  if (query.isError) return <ErrorState error={query.error} onRetry={() => query.refetch()} title="Applications could not be loaded" />;

  const { clients, viewerIsPlatformAdmin, protectedClients } = query.data;

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Applications</h1>
          <p>
            The systems that sign in through SSO: their addresses, whether they are switched on, their secrets and how much they are used.
            {viewerIsPlatformAdmin ? '' : ' Changes here belong to the platform administrator; you can see everything but the secrets.'}
          </p>
        </div>
      </div>

      {clients.map((c) => {
        const isProtected = protectedClients.includes(c.clientId);
        return (
          <section key={c.clientId} className="admin-card" aria-labelledby={`client-${c.clientId}`}>
            <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', flexWrap: 'wrap', justifyContent: 'space-between' }}>
              <div style={{ minWidth: 0 }}>
                <h2 id={`client-${c.clientId}`} style={{ margin: 0, fontSize: 17, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  {c.name}
                  <span className={`admin-badge ${c.active ? 'on' : 'off'}`}>{c.active ? 'Active' : 'Switched off'}</span>
                  {isProtected ? <span className="ui-chip lock"><Lock size={11} aria-hidden="true" /> Protected</span> : null}
                </h2>
                <p className="sub" style={{ margin: '4px 0 0' }}>
                  <code className="admin-code">{c.clientId}</code> · {c.pattern}
                </p>
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                {c.entitledUsers !== null ? (
                  <Link href={`/admin/clients/${c.clientId}`} className="admin-btn secondary">
                    <Users size={14} aria-hidden="true" /> {c.entitledUsers} {c.entitledUsers === 1 ? 'person' : 'people'} may open it
                  </Link>
                ) : null}
              </div>
            </div>

            {c.critical ? <p className="admin-hint" role="note">{c.critical}</p> : null}
            {c.secretIsDevDefault ? (
              <p className="sui-warn" role="alert" style={{ color: 'var(--warning-text)', fontSize: 13, margin: '12px 0 0', display: 'flex', gap: 8, alignItems: 'center' }}>
                <AlertTriangle size={16} aria-hidden="true" /> This client still uses a well-known development secret. Fine on a development machine; replace it before this runs for real.
              </p>
            ) : null}
            {c.urisDrift ? (
              <p role="status" style={{ color: 'var(--warning-text)', fontSize: 13, margin: '10px 0 0', display: 'flex', gap: 8, alignItems: 'center' }}>
                <AlertTriangle size={16} aria-hidden="true" /> The stored addresses differ from the server&apos;s configuration (changed here earlier, or the configuration changed since). “Restore configured addresses” puts them back in line.
              </p>
            ) : null}

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 22, marginTop: 18 }}>
              <UriList title="Where sign-ins are sent (redirect addresses)" uris={c.redirectUris} empty="None." />
              <UriList title="Where people land after signing out" uris={c.postLogoutRedirectUris} empty="None registered; the application shows its own sign-out page." />
              <div>
                <div className="sub" style={{ margin: '0 0 6px', fontWeight: 600 }}>What it may ask for</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {c.scopes.length === 0 ? <span className="admin-hint">No restriction</span> : c.scopes.map((s) => <span key={s} className="ui-chip">{s}</span>)}
                </div>
                <p className="admin-hint">
                  Grants: {c.grantTypes.join(', ')}. Client authentication: {c.authMethod.replace(/_/g, ' ')}. PKCE required for every request.
                  {c.rolesScope ? ` Its roles travel in the “${c.rolesScope}” scope only; no other system's roles are sent.` : ''}
                </p>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12, marginTop: 18 }}>
              {[
                ['Sign-ins held', c.usage.activeGrants],
                ['Renewable sessions', c.usage.activeRefreshTokens],
                ['Live access tokens', c.usage.activeAccessTokens],
                ['Last token issued', c.usage.lastTokenIssuedAt ? timeAgo(c.usage.lastTokenIssuedAt) : 'never'],
              ].map(([label, value]) => (
                <div key={String(label)} className="health-card" style={{ padding: '10px 14px' }}>
                  <div className="sub" style={{ margin: 0 }}>{label}</div>
                  <div style={{ fontSize: 20, fontWeight: 700 }}>{value}</div>
                </div>
              ))}
            </div>

            <p className="admin-hint" style={{ marginTop: 14 }}>
              <KeyRound size={12} aria-hidden="true" style={{ verticalAlign: '-1px' }} /> Secret: {secretAge(c)}. Last changed {timeAgo(c.updatedAt)}{c.updatedBy ? ` by ${c.updatedBy}` : ''}.
            </p>

            {viewerIsPlatformAdmin ? (
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
                {!isProtected ? (
                  <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => openEdit(c)}>
                    <Pencil size={14} aria-hidden="true" /> Edit addresses
                  </button>
                ) : null}
                <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => restore(c)}>
                  <RotateCcw size={14} aria-hidden="true" /> Restore configured addresses
                </button>
                {!isProtected ? (
                  <>
                    <button type="button" className="admin-btn secondary" disabled={busy} onClick={() => { setRotating(c); setRotateConfirm(''); setRotateError(null); }}>
                      <KeyRound size={14} aria-hidden="true" /> Rotate secret
                    </button>
                    <button type="button" className={`admin-btn ${c.active ? 'danger' : ''}`} disabled={busy} onClick={() => toggle(c)}>
                      <Power size={14} aria-hidden="true" /> {c.active ? 'Switch off' : 'Switch on'}
                    </button>
                  </>
                ) : null}
              </div>
            ) : null}
          </section>
        );
      })}

      <Modal
        open={editing !== null}
        title={editing ? `Addresses for ${editing.name}` : ''}
        onClose={() => setEditing(null)}
        dismissible={!busy}
        width={640}
        footer={
          <>
            <button type="button" className="admin-btn secondary" onClick={() => setEditing(null)} disabled={busy}>Cancel</button>
            <button type="button" className="admin-btn" onClick={saveEdit} disabled={busy}>{busy ? 'Saving…' : 'Save addresses'}</button>
          </>
        }
      >
        <p className="ui-modal-text">One address per line, each a complete https:// address. An address that is not listed here cannot receive a sign-in. They apply to the next sign-in; nobody is signed out.</p>
        <label className="ui-field" style={{ marginTop: 12 }}>
          <span className="sub">Redirect addresses (at least one)</span>
          <textarea className="ui-input" rows={4} value={redirectText} onChange={(e) => setRedirectText(e.target.value)} spellCheck={false} style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }} data-autofocus />
        </label>
        <label className="ui-field" style={{ marginTop: 12 }}>
          <span className="sub">Sign-out addresses (optional)</span>
          <textarea className="ui-input" rows={3} value={logoutText} onChange={(e) => setLogoutText(e.target.value)} spellCheck={false} style={{ fontFamily: 'ui-monospace, monospace', fontSize: 12 }} />
        </label>
        {editError ? <p className="ui-field-error" role="alert">{editError}</p> : null}
      </Modal>

      <Modal
        open={rotating !== null}
        title={rotating ? `Rotate the secret for ${rotating.name}?` : ''}
        onClose={() => setRotating(null)}
        dismissible={!busy}
        footer={
          <>
            <button type="button" className="admin-btn secondary" onClick={() => setRotating(null)} disabled={busy}>Cancel</button>
            <button type="button" className="admin-btn danger" onClick={rotate} disabled={busy || rotateConfirm !== rotating?.clientId}>{busy ? 'Rotating…' : 'Rotate secret'}</button>
          </>
        }
      >
        <div className="ui-modal-text">
          <p>A new secret is generated and the old one stops working at once. It is shown <strong>one time</strong>.</p>
          {rotating?.secretNote ? <p>{rotating.secretNote}</p> : null}
        </div>
        <label className="ui-field" style={{ marginTop: 14 }}>
          <span className="sub">Type <strong>{rotating?.clientId}</strong> to confirm</span>
          <input className="ui-input" value={rotateConfirm} onChange={(e) => setRotateConfirm(e.target.value)} autoComplete="off" data-autofocus />
        </label>
        {rotateError ? <p className="ui-field-error" role="alert">{rotateError}</p> : null}
      </Modal>

      <Modal
        open={revealed !== null}
        title="New secret"
        onClose={() => undefined}
        dismissible={false}
        width={560}
        footer={<button type="button" className="admin-btn" disabled={!saved} onClick={() => setRevealed(null)}>Done</button>}
      >
        <p className="ui-modal-text">This is the only time the secret for <strong>{revealed?.client.name}</strong> is shown. Copy it now; it cannot be shown again (rotate again if it is lost).</p>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', margin: '12px 0' }}>
          <code className="admin-code" style={{ flex: 1, padding: '10px 12px', wordBreak: 'break-all', fontSize: 13, userSelect: 'all' }}>{revealed?.secret}</code>
          <CopyButton text={revealed?.secret ?? ''} label="Copy the secret" />
        </div>
        {revealed?.client.secretNote ? <p className="ui-modal-text">{revealed.client.secretNote}</p> : null}
        <label className="ui-switch" style={{ marginTop: 12 }}>
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} data-autofocus />
          <span className="track" aria-hidden="true" />
          <span>I have saved the secret</span>
        </label>
      </Modal>
    </>
  );
}
