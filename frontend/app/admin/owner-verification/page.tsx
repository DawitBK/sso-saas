'use client';

import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { Copy, EyeOff, KeyRound } from 'lucide-react';
import { ApiError, adminFetch } from '@shared/lib/adminApi';
import { ErrorState, PageSkeleton } from '@shared/ui/States';
import { OwnerVerificationDialog } from '@shared/owner/OwnerVerificationDialog';
import { OWNER_BASE, SERVER_COMMANDS, emailReasonText, formatCountdown, recoveryCodesNote, secondsUntil, type OperationEntry, type OwnerStatus, type Ticket } from '@shared/owner/ownerLogic';
import { useNow } from '@shared/owner/useNow';

const TONE_BADGE = { success: 'ui-badge-success', warning: 'ui-badge-warning', danger: 'ui-badge-danger' } as const;

/** An authorisation for another system, shown once. It lives only in this component's state: never stored, gone on leaving the page. */
function TicketCard({ ticket, onHide }: { ticket: Ticket; onHide: () => void }) {
  const expiresMs = new Date(ticket.expiresAt).getTime();
  const now = useNow(true);
  const left = now === null ? null : secondsUntil(expiresMs, now);
  const expired = left !== null && left <= 0;

  async function copy() {
    try {
      await navigator.clipboard.writeText(ticket.ticket);
      toast.success('Copied');
    } catch {
      toast.error('Could not copy. Select the text and copy it by hand.');
    }
  }

  if (expired) {
    return (
      <div className="admin-card owner-ticket" role="status">
        <p style={{ margin: 0 }}>This authorisation has run out. Authorise the action again if you still need it.</p>
        <div className="owner-actions"><button type="button" className="admin-btn secondary" onClick={onHide}>Close</button></div>
      </div>
    );
  }
  return (
    <div className="admin-card owner-ticket">
      <h2 className="admin-section-title" style={{ margin: '0 0 8px' }}>Your authorisation code</h2>
      <label className="sub" htmlFor="owner-ticket-text" style={{ display: 'block', fontSize: 12, fontWeight: 600, color: 'var(--muted)', marginBottom: 5 }}>
        Shown once. Do not share it or save it anywhere.
      </label>
      <textarea id="owner-ticket-text" className="ui-input owner-ticket-text" readOnly rows={3} value={ticket.ticket} onFocus={(e) => e.currentTarget.select()} />
      <p className="admin-hint">Paste it into the other system&rsquo;s &ldquo;Owner authorisation&rdquo; field within 5 minutes. It works once.</p>
      <p className="owner-countdown">{left === null ? '' : `Runs out in ${formatCountdown(left)}`}</p>
      <div className="owner-actions">
        <button type="button" className="admin-btn secondary" onClick={onHide}><EyeOff size={14} aria-hidden="true" /> Hide it now</button>
        <button type="button" className="admin-btn" onClick={() => void copy()}><Copy size={14} aria-hidden="true" /> Copy</button>
      </div>
    </div>
  );
}

function OtherSystems({ operations, onAuthorised }: { operations: OperationEntry[]; onAuthorised: () => void }) {
  const others = operations.filter((o) => o.audience === 'dms');
  const [key, setKey] = useState('');
  const [open, setOpen] = useState(false);
  const [ticket, setTicket] = useState<Ticket | null>(null);
  const chosen = others.find((o) => o.key === (key || others[0]?.key));

  return (
    <section className="admin-card" aria-labelledby="owner-other-title">
      <h2 id="owner-other-title" className="admin-section-title" style={{ margin: '0 0 8px' }}>Authorise an action in another system</h2>
      {others.length === 0 || !chosen ? (
        <p className="admin-hint" style={{ margin: 0 }}>No action in another system needs your owner authorisation right now.</p>
      ) : (
        <>
          <p className="admin-hint" style={{ margin: '0 0 12px' }}>
            Some actions in other systems (for example creating a tenant in DMS) need your authorisation too. Choose the action, go through the same checks, and you get a one-time code to paste there.
          </p>
          <div className="ui-field" style={{ maxWidth: 460 }}>
            <label className="sub" htmlFor="owner-op">Action</label>
            <select id="owner-op" className="ui-input" value={chosen.key} onChange={(e) => setKey(e.target.value)}>
              {others.map((o) => <option key={o.key} value={o.key}>{o.label}</option>)}
            </select>
            {chosen.warning ? <p className="ui-field-hint">{chosen.warning}</p> : null}
          </div>
          <div className="owner-actions" style={{ justifyContent: 'flex-start' }}>
            <button type="button" className="admin-btn" onClick={() => { setTicket(null); setOpen(true); }}>
              <KeyRound size={14} aria-hidden="true" /> Authorise this action
            </button>
          </div>
          {open ? (
            <OwnerVerificationDialog
              key={chosen.key}
              operation={chosen.key}
              target={null}
              label={chosen.label}
              warning={chosen.warning}
              needsTarget={chosen.needsTarget}
              onTicket={(t) => { setTicket(t); setOpen(false); onAuthorised(); }}
              onCancel={() => setOpen(false)}
            />
          ) : null}
        </>
      )}
      {ticket ? <TicketCard ticket={ticket} onHide={() => setTicket(null)} /> : null}
    </section>
  );
}

export default function OwnerVerificationPage() {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ['owner-verification-status'],
    queryFn: () => adminFetch<OwnerStatus>(`${OWNER_BASE}/status`),
    staleTime: 0,
    retry: false,
  });
  const now = useNow(Boolean(query.data?.locked));

  if (query.isPending) return <PageSkeleton rows={3} />;

  if (query.isError) {
    if (query.error instanceof ApiError && (query.error.status === 404 || query.error.status === 403)) {
      return (
        <>
          <div className="admin-page-header"><div><h1>Owner verification</h1></div></div>
          <div className="admin-card" role="note">
            <p className="admin-hint" style={{ margin: 0 }}>This page is for the platform administrator (the owner) only.</p>
          </div>
        </>
      );
    }
    return <ErrorState error={query.error} onRetry={() => query.refetch()} title="Owner verification could not be loaded" />;
  }

  const s = query.data;
  const recovery = recoveryCodesNote(s.recoveryCodesRemaining);
  const lockedMs = s.lockedUntil ? new Date(s.lockedUntil).getTime() : null;
  const lockLeft = lockedMs !== null && now !== null ? secondsUntil(lockedMs, now) : null;

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>Owner verification</h1>
          <p>Some actions are reserved to you, the owner: signing keys, licences, platform settings, who can administer sign-in, and a few more. Each one asks you to prove it is you, every time.</p>
        </div>
      </div>

      <section className="admin-card" aria-labelledby="owner-status-title">
        <h2 id="owner-status-title" className="admin-section-title" style={{ margin: '0 0 10px' }}>Status</h2>
        <dl className="owner-status">
          <div>
            <dt>Owner verification</dt>
            <dd>
              <span className={`ui-badge ${s.enrolled ? 'ui-badge-success' : 'ui-badge-warning'}`}>{s.enrolled ? 'Enrolled' : 'Not enrolled yet'}</span>
              <span className="owner-status-note">
                {s.enrolled ? '' : 'Set it up on the server first (see the commands below).'}
                {s.required ? ' It is required: owner-only actions are refused without it.' : ' It is not being enforced on this server at the moment.'}
              </span>
            </dd>
          </div>
          {s.enrolled ? (
            <div>
              <dt>Authenticator app</dt>
              <dd>
                <span className={`ui-badge ${s.authenticator === false ? 'ui-badge-warning' : 'ui-badge-success'}`}>{s.authenticator === false ? 'Not used' : 'Required'}</span>
                <span className="owner-status-note">
                  {s.authenticator === false
                    ? 'This enrolment was made without an authenticator app: two proofs are asked (security questions, then the mailed code or a recovery code). To add one, the server operator runs the recovery tool with the authenticator switched on.'
                    : 'Asked last, after the security questions and the mailed code.'}
                </span>
              </dd>
            </div>
          ) : null}
          <div>
            <dt>Code sent to your mailbox</dt>
            <dd>
              <span className={`ui-badge ${s.emailAvailable ? 'ui-badge-success' : 'ui-badge-warning'}`}>{s.emailAvailable ? 'Available' : 'Unavailable'}</span>
              {s.emailAvailable ? null : <span className="owner-status-note">{emailReasonText(s.emailUnavailableReason)}</span>}
            </dd>
          </div>
          <div>
            <dt>Offline recovery codes</dt>
            <dd>
              <span className={`ui-badge ${TONE_BADGE[recovery.tone]}`}>{s.recoveryCodesRemaining}</span>
              <span className="owner-status-note">{recovery.text}</span>
            </dd>
          </div>
          <div>
            <dt>Locked</dt>
            <dd>
              {s.locked ? (
                <>
                  <span className="ui-badge ui-badge-danger">Locked</span>
                  <span className="owner-status-note" role="status">
                    Too many wrong answers.{' '}
                    {s.lockedUntil ? `Locked until ${new Date(s.lockedUntil).toLocaleTimeString()}` : ''}
                    {lockLeft !== null && lockLeft > 0 ? ` (${formatCountdown(lockLeft)} left).` : '.'}
                  </span>
                </>
              ) : (
                <span className="ui-badge ui-badge-success">No</span>
              )}
            </dd>
          </div>
        </dl>
        <div className="owner-actions" style={{ justifyContent: 'flex-start' }}>
          <button type="button" className="admin-btn secondary" onClick={() => void query.refetch()} disabled={query.isFetching}>Check again</button>
        </div>
      </section>

      <section className="admin-card" aria-labelledby="owner-how-title">
        <h2 id="owner-how-title" className="admin-section-title" style={{ margin: '0 0 8px' }}>How this works</h2>
        <ol className="owner-help">
          <li>When you do something reserved to the owner, a window opens and says what you are about to do.</li>
          <li>You answer your three security questions.</li>
          <li>You type the code sent to your mailbox. If mail cannot be sent, you use one of your offline recovery codes instead.</li>
          {s.authenticator === false ? null : <li>You type the 6 digits from your authenticator app.</li>}
          <li>The action then goes through. The permission works once, for that action only, and runs out after about 5 minutes.</li>
        </ol>
        <details className="owner-details">
          <summary>If something goes wrong</summary>
          <ul className="owner-help">
            <li><strong>Wrong answers.</strong> Each wrong answer or code uses up an attempt. After too many, verification locks for a while. Wait, then start again.</li>
            <li><strong>No mailed code.</strong> Check the spam folder, then use &ldquo;Send a new code&rdquo;. If mail is unavailable the window offers a recovery code instead.</li>
            <li><strong>Lost your authenticator app (if you use one) or your recovery codes.</strong> Nothing here can fix that. The recovery tool on the server (below) proves who you are again and replaces them.</li>
            <li><strong>The window took too long.</strong> It expires on its own. Nothing was changed. Start the action again.</li>
            <li><strong>Never share</strong> your answers, codes or authorisation with anyone, and never type them anywhere except this window.</li>
          </ul>
        </details>
      </section>

      <section className="admin-card" aria-labelledby="owner-cmd-title">
        <h2 id="owner-cmd-title" className="admin-section-title" style={{ margin: '0 0 8px' }}>Setting up and recovering (on the server)</h2>
        <p className="admin-hint" style={{ margin: '0 0 12px' }}>
          These are run by the server operator at a terminal, in the <code className="admin-code">SSO/backend</code> folder on the server. Your answers are typed there, never on this page.
        </p>
        <ul className="owner-commands">
          {SERVER_COMMANDS.map((c) => (
            <li key={c.command}>
              <code className="admin-code owner-command">{c.command}</code>
              <span>{c.what}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="admin-card" aria-labelledby="owner-ops-title">
        <h2 id="owner-ops-title" className="admin-section-title" style={{ margin: '0 0 8px' }}>Actions that need your authorisation</h2>
        {s.operations.length === 0 ? (
          <p className="admin-empty-row">None are listed.</p>
        ) : (
          <table className="admin-table">
            <thead><tr><th>Action</th><th>What to know</th><th>Where</th></tr></thead>
            <tbody>
              {s.operations.map((o) => (
                <tr key={o.key}>
                  <td>{o.label}</td>
                  <td style={{ color: 'var(--muted)' }}>{o.warning}</td>
                  <td>{o.audience === 'dms' ? 'Another system (DMS)' : 'This console'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <OtherSystems operations={s.operations} onAuthorised={() => void queryClient.invalidateQueries({ queryKey: ['owner-verification-status'] })} />
    </>
  );
}
