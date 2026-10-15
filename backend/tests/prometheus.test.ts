/**
 * The Prometheus exposition (ops/prometheus.ts, ops/httpStats.ts): valid text format, bounded labels, honest values, and the rule for when
 * the metrics route answers in Prometheus text instead of JSON.
 */
import type { Request } from 'express';
import { Exposition, renderPrometheus, wantsPrometheus } from '../src/ops/prometheus.js';
import { LATENCY_BUCKETS_SECONDS, areaOf, observeRequest, resetHttpStats, snapshotHttpStats } from '../src/ops/httpStats.js';

const system = {
  readiness: {
    status: 'degraded',
    checks: { database: { state: 'ok' }, redis: { state: 'off' }, dms: { state: 'degraded', detail: 'x' }, auditChain: { state: 'ok' } },
    startedAt: '2026-10-11T08:00:00.000Z',
    uptimeSeconds: 120,
    checkedAt: '2026-10-11T08:02:00.000Z',
  },
  peers: [
    { name: 'dms', state: 'down' },
    { name: 'gms', state: 'ok' },
  ],
  breakers: [{ name: 'dms-roles', state: 'open', consecutiveFailures: 5, shortCircuited: 7 }],
  jobs: [
    { name: 'purge', everySeconds: 3600, lastRunAt: '2026-10-11T08:00:00.000Z', lastOkAt: '2026-10-11T08:00:00.000Z', lastError: null, runs: 2, failures: 1, overdue: false },
    { name: 'audit-chain', everySeconds: 21600, lastRunAt: null, lastOkAt: null, lastError: null, runs: 0, failures: 0, overdue: false },
  ],
  passwordChecks: { max: 3, running: 1, waiting: 2, refused: 4, completed: 90 },
  notifications: { pending: 3, oldestPendingSeconds: null, abandonedLast7Days: 1 },
  database: { poolMax: 10, poolTotal: 4, poolIdle: 3, poolWaiting: 0 },
  process: { pid: 1, node: 'v24.0.0', version: '1.0.0', environment: 'production', startedAt: '2026-10-11T08:00:00.000Z', uptimeSeconds: 120, rssMb: 100, heapUsedMb: 50 },
  supervisor: { supervised: true, supervisorPid: 2, restarts: 3, watchdogKills: 1, lastExit: null },
} as unknown as Parameters<typeof renderPrometheus>[0]['system'];

const platform = { users_total: 10, users_active: 9, users_mfa_enrolled: 4, sessions_sso_active: 2, sessions_portal_active: 3, sessions_gateway_active: 0, logins_attempted_1h: 20, logins_failed_1h: 5, signing_keys_active: 1, users_mfa_secret_undecryptable: 0 };

const req = (query: Record<string, string>, accept?: string) => ({ query, headers: accept ? { accept } : {} }) as unknown as Request;

afterEach(() => resetHttpStats());

describe('renderPrometheus', () => {
  const text = () => {
    observeRequest('api', 200, 0.02);
    observeRequest('api', 200, 0.4);
    observeRequest('oidc', 503, 3);
    return renderPrometheus({ platform, system, http: snapshotHttpStats(), auditChain: { checkedAt: '2026-10-11T08:01:00.000Z', valid: false, checked: 10, openBreaks: 2, acknowledgedBreaks: 1, firstOpenBreak: '4' } });
  };

  it('is valid text exposition: every sample line is "name{labels} number", each metric has one HELP and one TYPE', () => {
    const out = text();
    expect(out.endsWith('\n')).toBe(true);
    const names = new Set<string>();
    for (const line of out.trim().split('\n')) {
      if (line.startsWith('# HELP ')) continue;
      if (line.startsWith('# TYPE ')) {
        const name = line.split(' ')[2];
        expect(names.has(name)).toBe(false);
        names.add(name);
        continue;
      }
      expect(line).toMatch(/^[a-zA-Z_:][a-zA-Z0-9_:]*(\{([a-zA-Z_][a-zA-Z0-9_]*="[^"\\\n]*(\\.[^"\\\n]*)*",?)*\})? -?\d+(\.\d+)?(e[+-]?\d+)?$/);
    }
    expect(names.size).toBeGreaterThan(30);
  });

  it('reports the facts the System page shows', () => {
    const out = text();
    expect(out).toContain('sso_readiness_status{status="degraded"} 1');
    expect(out).toContain('sso_readiness_status{status="ready"} 0');
    expect(out).toContain('sso_readiness_check{check="redis",state="off"} 1');
    expect(out).toContain('sso_peer_up{peer="dms"} 0');
    expect(out).toContain('sso_peer_up{peer="gms"} 1');
    expect(out).toContain('sso_circuit_breaker_state{breaker="dms-roles",state="open"} 1');
    expect(out).toContain('sso_circuit_breaker_short_circuited_total{breaker="dms-roles"} 7');
    expect(out).toContain('sso_job_failures_total{job="purge"} 1');
    expect(out).toContain('sso_job_last_success_timestamp_seconds{job="audit-chain"} 0');
    expect(out).toContain('sso_password_checks_refused_total 4');
    expect(out).toContain('sso_notifications_abandoned_7d 1');
    expect(out).toContain('sso_supervised 1');
    expect(out).toContain('sso_audit_chain_valid 0');
    expect(out).toContain('sso_audit_chain_open_breaks 2');
    expect(out).toContain('sso_audit_chain_acknowledged_breaks 1');
    expect(out).toContain('sso_users{state="mfa_enrolled"} 4');
  });

  it('declares the audit-chain gauges but gives them no value before the first verification', () => {
    const out = renderPrometheus({ platform, system, http: [], auditChain: null });
    expect(out).toContain('# TYPE sso_audit_chain_valid gauge');
    expect(out).not.toMatch(/^sso_audit_chain_valid /m);
  });

  it('http histograms are cumulative and end with +Inf equal to the count', () => {
    const out = text();
    const api = out.split('\n').filter((l) => l.startsWith('sso_http_request_duration_seconds_bucket{area="api",status="2xx"'));
    expect(api).toHaveLength(LATENCY_BUCKETS_SECONDS.length + 1);
    const counts = api.map((l) => Number(l.split(' ')[1]));
    expect([...counts].sort((a, b) => a - b)).toEqual(counts);
    expect(counts[counts.length - 1]).toBe(2);
    expect(out).toContain('sso_http_request_duration_seconds_count{area="api",status="2xx"} 2');
    expect(out).toContain('sso_http_requests_total{area="oidc",status="5xx"} 1');
  });

  it('escapes label values and refuses a metric declared twice', () => {
    const e = new Exposition();
    e.metric('x', 'gauge', 'h', [{ labels: { v: 'a"b\\c\nd' }, value: 1 }]);
    expect(e.toString()).toContain('x{v="a\\"b\\\\c\\nd"} 1');
    expect(() => e.metric('x', 'gauge', 'h', [])).toThrow(/twice/);
  });

  it('contains no secret-shaped content', () => {
    // `sso_totp_undecryptable_secrets_total` is a count, so the word is allowed; values, keys and connection strings are not.
    expect(text()).not.toMatch(/password_hash|postgres:\/\/|api[_-]?key|x-metrics-key|cookie|BEGIN [A-Z ]*KEY/i);
  });
});

describe('http labels stay bounded', () => {
  it('maps a path to a fixed area, never to the raw URL', () => {
    expect(areaOf('/api/v1/admin/users/8d1f4c1e-0000-0000-0000-000000000000?x=1')).toBe('api');
    expect(areaOf('/authorize/abc123')).toBe('oidc');
    expect(areaOf('/.well-known/openid-configuration')).toBe('oidc');
    expect(areaOf('/interaction/uid-xyz/login')).toBe('interaction');
    expect(areaOf('/health/ready')).toBe('health');
    expect(areaOf('/some/random/path')).toBe('other');
    expect(areaOf('/__proto__/x')).toBe('other');
    expect(areaOf('/')).toBe('other');
  });
});

describe('wantsPrometheus', () => {
  it('answers Prometheus text for ?format=prometheus and for a scraper Accept header, JSON otherwise', () => {
    expect(wantsPrometheus(req({ format: 'prometheus' }))).toBe(true);
    expect(wantsPrometheus(req({}, 'application/openmetrics-text;version=1.0.0,text/plain;version=0.0.4;q=0.5,*/*;q=0.1'))).toBe(true);
    expect(wantsPrometheus(req({}, 'text/plain'))).toBe(true);
    expect(wantsPrometheus(req({}))).toBe(false);
    expect(wantsPrometheus(req({}, '*/*'))).toBe(false);
    expect(wantsPrometheus(req({}, 'application/json'))).toBe(false);
    expect(wantsPrometheus(req({}, 'text/html,application/xhtml+xml'))).toBe(false);
    expect(wantsPrometheus(req({ format: 'json' }, 'application/json, text/plain'))).toBe(false);
  });
});
