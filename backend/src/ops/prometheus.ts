/**
 * Prometheus text exposition (version 0.0.4) of how SSO is doing: the same facts as the System page, in the form a scraper reads.
 *
 * No user data and no secrets: totals, states and timestamps only. Who may read it is decided by metricsAccessAllowed (ops/metrics.ts):
 * a signed-in administrator, a caller presenting METRICS_API_KEY as `x-metrics-key` (what a scraper uses), or anyone if
 * ENABLE_PUBLIC_METRICS_ROUTE is on.
 *
 * Scrape config (the backend's own port; Apache does not route /metrics):
 *   - job_name: sso
 *     metrics_path: /metrics
 *     params: { format: [prometheus] }
 *     static_configs: [{ targets: ['127.0.0.1:7300'] }]      # 9300 on the mirror
 *     # the scraper must send the header  x-metrics-key: <METRICS_API_KEY>
 */
import type { Request } from 'express';
import { collectPlatformMetrics } from './metrics.js';
import { collectSystem } from './system.js';
import { lastAuditChainState } from './auditChain.js';
import { LATENCY_BUCKETS_SECONDS, snapshotHttpStats, type HttpSeries } from './httpStats.js';

export const PROMETHEUS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

/**
 * `?format=prometheus`, or an Accept header that asks for Prometheus/OpenMetrics text and not JSON.
 * A bare wildcard Accept (curl's default) still gets the JSON this route always returned.
 */
export function wantsPrometheus(req: Request): boolean {
  if (String(req.query.format ?? '').toLowerCase() === 'prometheus') return true;
  const accept = String(req.headers.accept ?? '');
  return /openmetrics-text|text\/plain/.test(accept) && !/application\/json/.test(accept);
}

type Labels = Record<string, string | number>;

function esc(v: string | number): string {
  return String(v).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function fmt(labels?: Labels): string {
  if (!labels || Object.keys(labels).length === 0) return '';
  return `{${Object.entries(labels)
    .map(([k, v]) => `${k}="${esc(v)}"`)
    .join(',')}}`;
}

function num(v: number): string {
  return Number.isFinite(v) ? String(v) : '0';
}

/** Builds the text; every metric name is declared once with its HELP and TYPE, then its samples. */
export class Exposition {
  private out: string[] = [];
  private declared = new Set<string>();

  private declare(name: string, type: string, help: string): void {
    if (this.declared.has(name)) throw new Error(`metric ${name} declared twice`);
    this.declared.add(name);
    this.out.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
  }

  metric(name: string, type: 'gauge' | 'counter', help: string, samples: Array<{ labels?: Labels; value: number }>): void {
    this.declare(name, type, help);
    for (const s of samples) this.out.push(`${name}${fmt(s.labels)} ${num(s.value)}`);
  }

  histogram(name: string, help: string, series: Array<{ labels: Labels; count: number; sum: number; buckets: number[] }>): void {
    this.declare(name, 'histogram', help);
    for (const s of series) {
      LATENCY_BUCKETS_SECONDS.forEach((le, i) => this.out.push(`${name}_bucket${fmt({ ...s.labels, le })} ${s.buckets[i]}`));
      this.out.push(`${name}_bucket${fmt({ ...s.labels, le: '+Inf' })} ${s.count}`, `${name}_sum${fmt(s.labels)} ${num(s.sum)}`, `${name}_count${fmt(s.labels)} ${s.count}`);
    }
  }

  toString(): string {
    return `${this.out.join('\n')}\n`;
  }
}

type SystemView = Awaited<ReturnType<typeof collectSystem>>;

/** Pure: the exposition for already-collected data (what the tests drive). */
export function renderPrometheus(input: { platform: Record<string, number>; system: SystemView; http: HttpSeries[]; auditChain: ReturnType<typeof lastAuditChainState> }): string {
  const { platform: p, system: s, http } = input;
  const e = new Exposition();
  const ts = (iso: string | null | undefined): number => (iso ? Math.floor(new Date(iso).getTime() / 1000) : 0);

  e.metric('sso_up', 'gauge', 'Always 1 while this process answers.', [{ value: 1 }]);
  e.metric('sso_build_info', 'gauge', 'Version, Node version and environment of this process.', [
    { labels: { version: s.process.version, node: s.process.node, environment: s.process.environment }, value: 1 },
  ]);
  e.metric('sso_process_start_time_seconds', 'gauge', 'Unix time this process started.', [{ value: ts(s.process.startedAt) }]);
  e.metric('sso_process_uptime_seconds', 'gauge', 'Seconds since this process started.', [{ value: s.process.uptimeSeconds }]);
  e.metric('sso_process_resident_memory_bytes', 'gauge', 'Resident memory of this process.', [{ value: s.process.rssMb * 1048576 }]);
  e.metric('sso_process_heap_used_bytes', 'gauge', 'Used V8 heap of this process.', [{ value: s.process.heapUsedMb * 1048576 }]);

  e.metric('sso_supervised', 'gauge', '1 when deploy/supervise.cjs is supervising this process.', [{ value: s.supervisor.supervised ? 1 : 0 }]);
  e.metric('sso_supervisor_restarts_total', 'counter', 'Times the supervisor has restarted SSO.', [{ value: s.supervisor.restarts }]);
  e.metric('sso_supervisor_watchdog_kills_total', 'counter', 'Times the supervisor killed a running but unresponsive SSO.', [{ value: s.supervisor.watchdogKills }]);

  e.metric(
    'sso_readiness_status',
    'gauge',
    '1 for the current readiness status (ready, degraded or not_ready).',
    (['ready', 'degraded', 'not_ready'] as const).map((status) => ({ labels: { status }, value: s.readiness.status === status ? 1 : 0 })),
  );
  e.metric(
    'sso_readiness_check',
    'gauge',
    '1 for the current state of each readiness check (ok, degraded, down or off).',
    Object.entries(s.readiness.checks).map(([check, c]) => ({ labels: { check, state: c.state }, value: 1 })),
  );

  e.metric('sso_users', 'gauge', 'Accounts, by state (the platform administrator is not counted).', [
    { labels: { state: 'total' }, value: p.users_total ?? 0 },
    { labels: { state: 'active' }, value: p.users_active ?? 0 },
    { labels: { state: 'mfa_enrolled' }, value: p.users_mfa_enrolled ?? 0 },
  ]);
  e.metric('sso_sessions_active', 'gauge', 'Live sessions, by kind.', [
    { labels: { kind: 'sso' }, value: p.sessions_sso_active ?? 0 },
    { labels: { kind: 'portal' }, value: p.sessions_portal_active ?? 0 },
    { labels: { kind: 'gateway' }, value: p.sessions_gateway_active ?? 0 },
  ]);
  e.metric('sso_logins_last_hour', 'gauge', 'Sign-in attempts in the last hour, by result.', [
    { labels: { result: 'attempted' }, value: p.logins_attempted_1h ?? 0 },
    { labels: { result: 'failed' }, value: p.logins_failed_1h ?? 0 },
  ]);
  e.metric('sso_signing_keys_active', 'gauge', 'Signing keys marked active (exactly 1 is healthy).', [{ value: p.signing_keys_active ?? 0 }]);
  e.metric('sso_totp_undecryptable_secrets_total', 'counter', 'Stored authenticator secrets that failed to decrypt since start (non-zero means TOTP_ENCRYPTION_KEY no longer matches).', [
    { value: p.users_mfa_secret_undecryptable ?? 0 },
  ]);

  e.metric('sso_job_runs_total', 'counter', 'Runs of each background job since start.', s.jobs.map((j) => ({ labels: { job: j.name }, value: j.runs })));
  e.metric('sso_job_failures_total', 'counter', 'Failed runs of each background job since start.', s.jobs.map((j) => ({ labels: { job: j.name }, value: j.failures })));
  e.metric('sso_job_last_success_timestamp_seconds', 'gauge', 'Unix time of each job last successful run (0 if none yet).', s.jobs.map((j) => ({ labels: { job: j.name }, value: ts(j.lastOkAt) })));
  e.metric('sso_job_overdue', 'gauge', '1 when a job has not started for more than twice its interval.', s.jobs.map((j) => ({ labels: { job: j.name }, value: j.overdue ? 1 : 0 })));

  e.metric('sso_password_checks', 'gauge', 'Password checks right now, by state.', [
    { labels: { state: 'running' }, value: s.passwordChecks.running },
    { labels: { state: 'waiting' }, value: s.passwordChecks.waiting },
  ]);
  e.metric('sso_password_checks_completed_total', 'counter', 'Password checks completed since start.', [{ value: s.passwordChecks.completed }]);
  e.metric('sso_password_checks_refused_total', 'counter', 'Sign-ins turned away as busy since start (a rising value means sign-in is being flooded).', [{ value: s.passwordChecks.refused }]);

  e.metric('sso_notifications_pending', 'gauge', 'Sign-out notices to DMS/GMS still waiting to get through.', [{ value: s.notifications.pending }]);
  e.metric('sso_notifications_oldest_pending_seconds', 'gauge', 'Age of the oldest pending notice (0 when none).', [{ value: s.notifications.oldestPendingSeconds ?? 0 }]);
  e.metric('sso_notifications_abandoned_7d', 'gauge', 'Notices given up on in the last 7 days.', [{ value: s.notifications.abandonedLast7Days }]);

  e.metric(
    'sso_peer_up',
    'gauge',
    '1 when DMS/GMS answered the last probe (omitted when switched off).',
    s.peers.filter((x) => x.state !== 'off').map((x) => ({ labels: { peer: x.name }, value: x.state === 'ok' ? 1 : 0 })),
  );
  e.metric(
    'sso_circuit_breaker_state',
    'gauge',
    '1 for the current state of each circuit breaker.',
    s.breakers.flatMap((b) => (['closed', 'open', 'half-open'] as const).map((state) => ({ labels: { breaker: b.name, state }, value: b.state === state ? 1 : 0 }))),
  );
  e.metric('sso_circuit_breaker_short_circuited_total', 'counter', 'Calls refused while a breaker was open.', s.breakers.map((b) => ({ labels: { breaker: b.name }, value: b.shortCircuited })));

  e.metric('sso_db_pool_connections', 'gauge', 'Database pool connections, by state.', [
    { labels: { state: 'total' }, value: s.database.poolTotal },
    { labels: { state: 'idle' }, value: s.database.poolIdle },
    { labels: { state: 'waiting' }, value: s.database.poolWaiting },
    { labels: { state: 'max' }, value: s.database.poolMax },
  ]);

  const chain = input.auditChain;
  e.metric('sso_audit_chain_valid', 'gauge', '1 when the last audit-chain verification found no unexplained break (absent until the first verification).', chain ? [{ value: chain.valid ? 1 : 0 }] : []);
  e.metric('sso_audit_chain_open_breaks', 'gauge', 'Unexplained breaks found by the last verification.', chain ? [{ value: chain.openBreaks }] : []);
  e.metric('sso_audit_chain_acknowledged_breaks', 'gauge', 'Breaks found by the last verification that a platform administrator has acknowledged.', chain ? [{ value: chain.acknowledgedBreaks }] : []);
  e.metric('sso_audit_chain_last_verified_timestamp_seconds', 'gauge', 'Unix time of the last audit-chain verification.', chain ? [{ value: ts(chain.checkedAt) }] : []);

  e.metric('sso_http_requests_total', 'counter', 'Requests answered, by area and status class.', http.map((h) => ({ labels: { area: h.area, status: h.statusClass }, value: h.count })));
  e.histogram(
    'sso_http_request_duration_seconds',
    'Time to answer a request, by area and status class.',
    http.map((h) => ({ labels: { area: h.area, status: h.statusClass }, count: h.count, sum: h.sum, buckets: h.buckets })),
  );

  return e.toString();
}

/** Collects everything and renders it. Throws if the database cannot be read; the route answers 503. */
export async function collectPrometheus(): Promise<string> {
  const [platform, system] = await Promise.all([collectPlatformMetrics(), collectSystem()]);
  return renderPrometheus({ platform, system, http: snapshotHttpStats(), auditChain: lastAuditChainState() });
}
