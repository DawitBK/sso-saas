'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { AlertTriangle, CheckCircle2, Clipboard, Pause, Play, RefreshCw, XCircle } from 'lucide-react';
import { adminFetch } from '@shared/lib/adminApi';
import { formatDateTime, formatDuration, timeAgo } from '@shared/lib/format';
import { ErrorState, PageSkeleton } from '@shared/ui/States';

type State = 'ok' | 'degraded' | 'down' | 'off';
interface Check { state: State; detail?: string }
interface Peer { name: 'dms' | 'gms'; state: State; checkedAt: string | null; latencyMs: number | null; detail?: string }
interface Job { name: string; everySeconds: number; lastRunAt: string | null; lastOkAt: string | null; lastError: string | null; runs: number; failures: number; overdue: boolean }
interface Breaker { name: string; state: 'closed' | 'open' | 'half-open'; consecutiveFailures: number; shortCircuited: number; lastFailureAt: string | null; lastSuccessAt: string | null; retryAt: string | null }
interface SystemData {
  readiness: { status: 'ready' | 'degraded' | 'not_ready'; checks: Record<string, Check>; startedAt: string; uptimeSeconds: number; checkedAt: string };
  peers: Peer[];
  breakers: Breaker[];
  jobs: Job[];
  database: { poolMax: number; poolTotal: number; poolIdle: number; poolWaiting: number };
  notifications: { pending: number; oldestPendingSeconds: number | null; abandonedLast7Days: number };
  passwordChecks: { max: number; running: number; waiting: number; refused: number; completed: number };
  process: { pid: number; node: string; version: string; environment: string; startedAt: string; uptimeSeconds: number; rssMb: number; heapUsedMb: number };
  supervisor: { supervised: boolean; supervisorPid: number | null; restarts: number; watchdogKills: number; lastExit: { code: number | null; signal: string | null; at: string; ranSeconds: number; reason: string } | null };
  supervisionExpected: boolean;
  config: Record<string, string | number | boolean>;
}

/** What each check is, and what it means for the people signing in, in plain words. */
const CHECKS: Record<string, { title: string; meaning: string }> = {
  database: { title: 'Database', meaning: 'Where accounts, sessions and settings live. Without it nobody can sign in.' },
  signingKeys: { title: 'Signing keys', meaning: 'Used to sign the tokens every application trusts. Without an active key no token can be issued.' },
  schema: { title: 'Database schema', meaning: 'Whether every migration that ships with this version has been applied.' },
  redis: { title: 'Redis', meaning: 'Optional. Shares rate-limit counters between processes. If it fails, limits fail open and sign-in continues.' },
  dms: { title: 'DMS reachability', meaning: 'Whether the document system answers. SSO signs people in without it, but cannot apply their DMS roles.' },
  gms: { title: 'GMS reachability', meaning: 'Whether the guest system answers. The GMS tile and its bridge need it.' },
  dmsRoleLookup: { title: 'DMS role lookup', meaning: 'Fetches a person’s DMS roles during sign-in. After repeated failures it pauses so sign-in stays fast.' },
  totpKey: { title: 'Authenticator secrets', meaning: 'Whether stored two-factor secrets can be decrypted with the current key. A mismatch locks enrolled people out.' },
  notifications: { title: 'Sign-out notifications', meaning: 'When someone is signed out or disabled, DMS and GMS are told. If one was down, SSO keeps retrying for 48 hours; this shows when something is stuck.' },
  auditChain: { title: 'Audit log integrity', meaning: 'Whether the administrative audit log still matches its own fingerprints. Checked every six hours; “Needs attention” means an entry was changed or removed and nobody has explained it yet. Open Audit Log and use Verify integrity.' },
  eventLoop: { title: 'Responsiveness', meaning: 'Whether this process is answering promptly. A long stall means it is overloaded or blocked.' },
};

const STATE_LABEL: Record<State, string> = { ok: 'Working', degraded: 'Needs attention', down: 'Down', off: 'Not in use' };

const BANNER = {
  ready: { icon: CheckCircle2, title: 'Everything is working', text: 'People can sign in and every connected system is answering.' },
  degraded: { icon: AlertTriangle, title: 'Working, with something to look at', text: 'SSO is signing people in, but at least one thing around it needs attention (below).' },
  not_ready: { icon: XCircle, title: 'Sign-in is not available', text: 'A part SSO cannot work without has failed. Fix the item marked Down.' },
} as const;

function Kv({ rows }: { rows: Array<[string, React.ReactNode]> }) {
  return (
    <dl className="kv">
      {rows.map(([k, v]) => (
        <div key={k} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export default function SystemPage() {
  const [auto, setAuto] = useState(true);
  const query = useQuery({
    queryKey: ['admin-system'],
    queryFn: () => adminFetch<SystemData>('/api/v1/admin/system'),
    staleTime: 0,
    refetchInterval: auto ? 15_000 : false,
  });

  if (query.isPending) return <PageSkeleton rows={3} />;
  if (query.isError) return <ErrorState error={query.error} onRetry={() => query.refetch()} title="System status could not be loaded" />;

  const d = query.data;
  const banner = BANNER[d.readiness.status];
  const Icon = banner.icon;

  async function copyDiagnostics() {
    try {
      await navigator.clipboard.writeText(JSON.stringify({ capturedAt: new Date().toISOString(), ...d }, null, 2));
      toast.success('Diagnostics copied. They contain no passwords, keys or connection strings.');
    } catch {
      toast.error('Could not copy to the clipboard.');
    }
  }

  return (
    <>
      <div className="admin-page-header">
        <div>
          <h1>System health</h1>
          <p>How this sign-in service and the systems around it are doing right now. Refreshes every 15 seconds.</p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" className="admin-btn secondary" onClick={() => query.refetch()} disabled={query.isFetching}>
            <RefreshCw size={14} aria-hidden="true" /> {query.isFetching ? 'Checking…' : 'Check now'}
          </button>
          <button type="button" className="admin-btn secondary" onClick={() => setAuto((a) => !a)} aria-pressed={!auto}>
            {auto ? <Pause size={14} aria-hidden="true" /> : <Play size={14} aria-hidden="true" />} {auto ? 'Pause refresh' : 'Resume refresh'}
          </button>
          <button type="button" className="admin-btn secondary" onClick={copyDiagnostics}>
            <Clipboard size={14} aria-hidden="true" /> Copy diagnostics
          </button>
        </div>
      </div>

      <div className={`health-banner ${d.readiness.status}`} role="status">
        <Icon size={26} aria-hidden="true" />
        <div>
          <strong>{banner.title}</strong>
          <div style={{ fontSize: 13 }}>{banner.text} Last checked {timeAgo(d.readiness.checkedAt)}.</div>
        </div>
      </div>

      {d.supervisionExpected && !d.supervisor.supervised ? (
        <div className="admin-card admin-alert-card" role="alert">
          <p className="alert-title">⚠ This process is not supervised</p>
          <p className="alert-row">
            If it crashes, nothing restarts it and nobody can sign in until someone starts it by hand. Start it with <code className="admin-code">npm run start:prod:supervised</code> (or <code className="admin-code">start:mirror:supervised</code>); production-start.bat already does.
          </p>
        </div>
      ) : null}

      <h2 className="admin-section-title">Checks</h2>
      <div className="health-grid">
        {Object.entries(d.readiness.checks).map(([key, check]) => {
          const meta = CHECKS[key] ?? { title: key, meaning: '' };
          return (
            <div key={key} className="health-card">
              <header>
                <span className={`ui-dot ${check.state}`} aria-hidden="true" />
                {meta.title}
                <span style={{ marginLeft: 'auto', fontSize: 12, fontWeight: 600, color: check.state === 'ok' ? 'var(--success-text)' : check.state === 'off' ? 'var(--muted)' : check.state === 'down' ? 'var(--danger)' : 'var(--warning-text)' }}>
                  {STATE_LABEL[check.state]}
                </span>
              </header>
              <p>{meta.meaning}</p>
              {check.detail ? <p style={{ color: 'var(--ink)' }}>{check.detail}</p> : null}
            </div>
          );
        })}
      </div>

      <h2 className="admin-section-title">Connected systems</h2>
      <div className="admin-card">
        <table className="admin-table">
          <thead><tr><th>System</th><th>State</th><th>Answer time</th><th>Last checked</th><th>Detail</th></tr></thead>
          <tbody>
            {d.peers.map((p) => (
              <tr key={p.name}>
                <td style={{ fontWeight: 600 }}>{p.name === 'dms' ? 'DMS' : 'GMS'}</td>
                <td><span className={`ui-dot ${p.state}`} aria-hidden="true" /> {STATE_LABEL[p.state]}</td>
                <td>{p.latencyMs === null ? '—' : `${p.latencyMs} ms`}</td>
                <td>{timeAgo(p.checkedAt)}</td>
                <td style={{ color: 'var(--muted)' }}>{p.detail ?? '—'}</td>
              </tr>
            ))}
            {d.breakers.map((b) => (
              <tr key={b.name}>
                <td style={{ fontWeight: 600 }}>DMS role lookup</td>
                <td><span className={`ui-dot ${b.state === 'closed' ? 'ok' : 'degraded'}`} aria-hidden="true" /> {b.state === 'closed' ? 'Normal' : b.state === 'open' ? 'Paused' : 'Trying again'}</td>
                <td>—</td>
                <td>{b.lastSuccessAt ? `last worked ${timeAgo(b.lastSuccessAt)}` : 'not yet'}</td>
                <td style={{ color: 'var(--muted)' }}>
                  {b.state === 'closed'
                    ? `${b.shortCircuited} sign-ins skipped it since start`
                    : `${b.consecutiveFailures} failures in a row; next attempt ${b.retryAt ? `at ${formatDateTime(b.retryAt)}` : 'soon'}`}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="admin-section-title">Background jobs</h2>
      <div className="admin-card">
        <table className="admin-table">
          <thead><tr><th>Job</th><th>Runs every</th><th>Last run</th><th>Last success</th><th>Result</th></tr></thead>
          <tbody>
            {d.jobs.length === 0 ? (
              <tr><td colSpan={5} className="admin-empty-row">No jobs have been registered yet.</td></tr>
            ) : d.jobs.map((j) => {
              return (
                <tr key={j.name}>
                  <td style={{ fontWeight: 600 }}>{j.name === 'purge' ? 'Clean-up of expired records' : j.name === 'ad-resync' ? 'Active Directory group re-check' : j.name}</td>
                  <td>{formatDuration(j.everySeconds)}</td>
                  <td>{timeAgo(j.lastRunAt)}</td>
                  <td>{timeAgo(j.lastOkAt)}</td>
                  <td>
                    {j.lastError ? <span className="ui-badge ui-badge-danger">Failing: {j.lastError}</span> : j.overdue ? <span className="ui-badge ui-badge-warning">Overdue</span> : <span className="ui-badge ui-badge-success">OK</span>}
                    <span style={{ color: 'var(--muted)', marginLeft: 8, fontSize: 12 }}>{j.runs} runs, {j.failures} failed</span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 18 }}>
        <div>
          <h2 className="admin-section-title">This process</h2>
          <div className="admin-card">
            <Kv rows={[
              ['Version', d.process.version],
              ['Environment', d.process.environment],
              ['Running for', `${formatDuration(d.process.uptimeSeconds)} (since ${formatDateTime(d.process.startedAt)})`],
              ['Process id', d.process.pid],
              ['Node.js', d.process.node],
              ['Memory', `${d.process.rssMb} MB in use (${d.process.heapUsedMb} MB heap)`],
              ['Supervisor', d.supervisor.supervised ? `Yes (pid ${d.supervisor.supervisorPid})` : 'None'],
              ['Restarts', d.supervisor.supervised ? `${d.supervisor.restarts} (${d.supervisor.watchdogKills} forced after not answering)` : '—'],
              ['Last exit', d.supervisor.lastExit ? `code ${d.supervisor.lastExit.code ?? '—'} after ${formatDuration(d.supervisor.lastExit.ranSeconds)}, ${timeAgo(d.supervisor.lastExit.at)} (${d.supervisor.lastExit.reason})` : '—'],
            ]} />
          </div>
        </div>
        <div>
          <h2 className="admin-section-title">Database connections</h2>
          <div className="admin-card">
            <Kv rows={[
              ['In use or open', `${d.database.poolTotal} of ${d.database.poolMax}`],
              ['Idle', d.database.poolIdle],
              ['Waiting for a connection', d.database.poolWaiting],
            ]} />
            <p className="admin-hint">Waiting above zero for long means the service needs more connections or a query is stuck.</p>
          </div>
        </div>
        <div>
          <h2 className="admin-section-title">Sign-in load</h2>
          <div className="admin-card">
            <Kv rows={[
              ['Sign-out notifications waiting', d.notifications.pending === 0 ? 'None' : `${d.notifications.pending} (oldest ${formatDuration(d.notifications.oldestPendingSeconds ?? 0)})`],
              ['Given up on in the last 7 days', d.notifications.abandonedLast7Days],
              ['Password checks running', `${d.passwordChecks.running} of ${d.passwordChecks.max} allowed at once`],
              ['Waiting their turn', d.passwordChecks.waiting],
              ['Done since start', d.passwordChecks.completed],
              ['Turned away as too busy', d.passwordChecks.refused],
            ]} />
            <p className="admin-hint">
              Checking a password is deliberately expensive, so only a few run at once and the rest queue briefly. “Turned away” counts sign-ins told to retry in a few seconds; if it keeps rising, someone is flooding the sign-in page.
            </p>
          </div>
        </div>
        <div>
          <h2 className="admin-section-title">Configuration</h2>
          <div className="admin-card">
            <Kv rows={[
              ['Address', String(d.config.issuer)],
              ['Served under', String(d.config.publicBasePath)],
              ['Proxy hops trusted', String(d.config.trustProxyHops)],
              ['Active Directory', String(d.config.activeDirectory)],
              ['DMS connection', d.config.dms ? 'On' : 'Off'],
              ['GMS bridge', d.config.gmsBridge ? 'On' : 'Off'],
              ['Redis', String(d.config.redis)],
              ['Sign-in lockout', d.config.lockoutEnabled ? 'On' : 'Off'],
              ['Two-factor required for administrators', d.config.adminTwoFactorRequired ? 'Yes' : 'No'],
            ]} />
            <p className="admin-hint">Policy values are changed under Settings; the rest are set in the server’s environment file.</p>
          </div>
        </div>
      </div>
    </>
  );
}
