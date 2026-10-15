/**
 * Readiness: ONE collector behind `/health/ready` and `/api/v1/health/ready` (they used to be two copies that drifted) and behind
 * the admin console's System page.
 *
 *   not_ready  a check SSO cannot work without has failed: the database, or no active signing key. HTTP 503.
 *   degraded   SSO is signing people in, but something around it is unwell: a pending migration, Redis (when configured), DMS or
 *              GMS unreachable, the DMS role lookup paused by its circuit breaker, a TOTP key mismatch, a stalled event loop.
 *              HTTP 200 on purpose: the uptime monitor and any load balancer must keep sending traffic here.
 *   ready      everything is fine.
 *
 * What an anonymous caller sees is the state words only (publicView). Reasons, versions and counters are for a signed-in
 * administrator (adminView): a raw error names the host, the database and the role.
 */
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { redisClient } from '../infrastructure/redis.js';
import { undecryptableSecretCount } from '../auth/totp.js';
import { dmsRolesBreaker } from '../auth/client-role-claims.js';
import { logger } from '../logging/logger.js';
import { getPeerStatuses } from './peers.js';
import { outboxStats } from './notificationOutbox.js';
import { auditChainCheck } from './auditChain.js';

export type CheckState = 'ok' | 'degraded' | 'down' | 'off';
export interface Check {
  state: CheckState;
  /** Operator-facing; never sent to an anonymous caller. */
  detail?: string;
}
export type ReadinessStatus = 'ready' | 'degraded' | 'not_ready';
export interface Readiness {
  status: ReadinessStatus;
  checks: Record<string, Check>;
  startedAt: string;
  uptimeSeconds: number;
  checkedAt: string;
}

/** Checks SSO cannot work without. */
const FATAL = new Set(['database', 'signingKeys']);
const CACHE_MS = 2_000;
const DB_TIMEOUT_MS = 3_000;
const LOOP_LAG_DEGRADED_MS = 500;

const startedAt = new Date();
const loopDelay = monitorEventLoopDelay({ resolution: 20 });
loopDelay.enable();

let cached: { at: number; value: Readiness } | null = null;
let schemaCache: { at: number; check: Check } | null = null;

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms} ms`)), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

async function databaseCheck(): Promise<Check> {
  try {
    await withTimeout(pool.query('SELECT 1'), DB_TIMEOUT_MS, 'database');
    return { state: 'ok' };
  } catch (err) {
    logger.error({ err }, '[idp:health] database check failed');
    return { state: 'down', detail: 'The database did not answer.' };
  }
}

async function signingKeysCheck(): Promise<Check> {
  try {
    const { rows } = await withTimeout(pool.query<{ n: string }>('SELECT COUNT(*) AS n FROM idp_signing_keys WHERE is_active'), DB_TIMEOUT_MS, 'signing keys');
    const n = Number(rows[0]?.n ?? 0);
    if (n === 0) return { state: 'down', detail: 'There is no active signing key; no token can be issued.' };
    if (n > 1) return { state: 'degraded', detail: `${n} keys are marked active; exactly one should be (rotation was bypassed).` };
    return { state: 'ok' };
  } catch {
    return { state: 'down', detail: 'The signing keys could not be read.' };
  }
}

async function schemaCheck(): Promise<Check> {
  if (schemaCache && Date.now() - schemaCache.at < 60_000) return schemaCache.check;
  let check: Check;
  try {
    // Loaded on first use: db/migrate.ts reads import.meta, so a static import would drag it into every module (and test) that
    // reaches the health routes.
    const { pendingMigrations } = await import('../db/migrate.js');
    const pending = await withTimeout(pendingMigrations(), DB_TIMEOUT_MS, 'migrations');
    check = pending.length === 0 ? { state: 'ok' } : { state: 'degraded', detail: `${pending.length} migration(s) not applied: ${pending.join(', ')}. Run npm run db:migrate (prod: db:migrate:prod).` };
  } catch {
    check = { state: 'degraded', detail: 'The migration list could not be compared.' };
  }
  schemaCache = { at: Date.now(), check };
  return check;
}

async function redisCheck(): Promise<Check> {
  if (!redisClient) return { state: 'off', detail: 'REDIS_URL is not set; rate limits are per process.' };
  try {
    await withTimeout(redisClient.ping(), 1_500, 'redis');
    return { state: 'ok' };
  } catch {
    return { state: 'degraded', detail: 'Redis did not answer; rate limiting is failing open.' };
  }
}

function peerCheck(name: 'dms' | 'gms'): Check {
  const peer = getPeerStatuses().find((p) => p.name === name);
  if (!peer || peer.state === 'off') return { state: 'off', detail: peer?.detail };
  if (peer.state === 'ok') return { state: 'ok' };
  // SSO signs people in without DMS or GMS, so an unreachable peer is a degraded SSO, never a not-ready one.
  return { state: 'degraded', detail: peer.detail ?? 'not reachable' };
}

function dmsRolesCheck(): Check {
  if (!IDP_CONFIG.dms.enabled) return { state: 'off' };
  if (!IDP_CONFIG.dmsInternalApiKey) return { state: 'degraded', detail: 'DMS_INTERNAL_API_KEY is not set; DMS roles are not applied.' };
  const snap = dmsRolesBreaker.snapshot();
  if (snap.state === 'closed') return { state: 'ok' };
  return { state: 'degraded', detail: `DMS role lookup is ${snap.state} after ${snap.consecutiveFailures} failures; sign-ins omit the DMS roles until it answers.` };
}

/** Sign-out notifications to DMS/GMS that have not got through (ops/notificationOutbox.ts). */
async function notificationsCheck(): Promise<Check> {
  try {
    const s = await withTimeout(outboxStats(), DB_TIMEOUT_MS, 'notifications');
    if (s.abandonedLast7Days > 0) return { state: 'degraded', detail: `${s.abandonedLast7Days} sign-out notification(s) to DMS or GMS were given up on after 48 hours; end those sessions there by hand.` };
    if (s.pending > 0 && (s.oldestPendingSeconds ?? 0) > 900) return { state: 'degraded', detail: `${s.pending} sign-out notification(s) to DMS or GMS are still waiting to get through (the oldest for ${Math.round((s.oldestPendingSeconds ?? 0) / 60)} minutes).` };
    return { state: 'ok' };
  } catch {
    // Table missing (migration 020 not applied yet) or unreadable: the schema check already reports a pending migration.
    return { state: 'ok' };
  }
}

function totpKeyCheck(): Check {
  const n = undecryptableSecretCount();
  return n === 0 ? { state: 'ok' } : { state: 'degraded', detail: `${n} stored authenticator secret(s) could not be decrypted since start; TOTP_ENCRYPTION_KEY no longer matches.` };
}

function eventLoopCheck(): Check {
  const p99 = loopDelay.percentile(99) / 1e6;
  loopDelay.reset();
  return p99 > LOOP_LAG_DEGRADED_MS ? { state: 'degraded', detail: `The event loop stalled for up to ${Math.round(p99)} ms.` } : { state: 'ok' };
}

export async function collectReadiness(): Promise<Readiness> {
  if (cached && Date.now() - cached.at < CACHE_MS) return cached.value;
  const [database, signingKeys, schema, redis, notifications] = await Promise.all([databaseCheck(), signingKeysCheck(), schemaCheck(), redisCheck(), notificationsCheck()]);
  const checks: Record<string, Check> = {
    database,
    signingKeys,
    schema,
    redis,
    dms: peerCheck('dms'),
    gms: peerCheck('gms'),
    dmsRoleLookup: dmsRolesCheck(),
    notifications,
    totpKey: totpKeyCheck(),
    auditChain: auditChainCheck(),
    eventLoop: eventLoopCheck(),
  };
  const fatalDown = Object.entries(checks).some(([name, c]) => FATAL.has(name) && c.state === 'down');
  const anyUnwell = Object.values(checks).some((c) => c.state === 'degraded' || c.state === 'down');
  const value: Readiness = {
    status: fatalDown ? 'not_ready' : anyUnwell ? 'degraded' : 'ready',
    checks,
    startedAt: startedAt.toISOString(),
    uptimeSeconds: Math.round(process.uptime()),
    checkedAt: new Date().toISOString(),
  };
  cached = { at: Date.now(), value };
  return value;
}

/** What an anonymous caller may see: state words only. `db` is kept for the callers that read it. */
export function publicView(r: Readiness): { status: ReadinessStatus; db: 'ok' | 'unreachable'; checks: Record<string, CheckState> } {
  return {
    status: r.status,
    db: r.checks.database?.state === 'ok' ? 'ok' : 'unreachable',
    checks: Object.fromEntries(Object.entries(r.checks).map(([k, c]) => [k, c.state])),
  };
}

export function httpStatusFor(r: Readiness): 200 | 503 {
  return r.status === 'not_ready' ? 503 : 200;
}

/** Test hook. */
export function resetReadinessCache(): void {
  cached = null;
  schemaCache = null;
}
