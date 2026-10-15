/**
 * Background reachability probes for the two systems SSO talks to, DMS and GMS.
 *
 * SSO can sign people in without either of them, so neither is a reason to refuse traffic; but an operator needs to see at a glance
 * that "DMS roles are not being applied because DMS is down". The probes run on a timer and the result is cached, so reading
 * readiness (ops/readiness.ts) never waits on another system and a flood of health requests cannot become a flood of calls into
 * DMS or GMS.
 *
 * DMS: GET <DMS_API_BASE_URL>/operations/ready (unauthenticated, 503 when its database, Redis or workers have failed).
 * GMS: GET <GMS_API_BASE>/health (liveness).
 */
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';

export type PeerState = 'ok' | 'degraded' | 'down' | 'off';

export interface PeerStatus {
  name: 'dms' | 'gms';
  state: PeerState;
  checkedAt: string | null;
  latencyMs: number | null;
  /** Operator-facing reason; never returned to an anonymous caller. */
  detail?: string;
}

const PROBE_EVERY_MS = 30_000;
const PROBE_TIMEOUT_MS = 3_000;

const statuses: Record<'dms' | 'gms', PeerStatus> = {
  dms: { name: 'dms', state: IDP_CONFIG.dms.enabled ? 'down' : 'off', checkedAt: null, latencyMs: null, detail: IDP_CONFIG.dms.enabled ? 'not probed yet' : 'DMS_ENABLED is false' },
  gms: { name: 'gms', state: IDP_CONFIG.gms.enabled ? 'down' : 'off', checkedAt: null, latencyMs: null, detail: IDP_CONFIG.gms.enabled ? 'not probed yet' : 'GMS_BRIDGE_ENABLED is false' },
};

/** Maps an HTTP answer to a state: 2xx fine; 503 means "answering but unwell"; anything else is down. */
export function stateForStatus(status: number): PeerState {
  if (status >= 200 && status < 300) return 'ok';
  if (status === 503) return 'degraded';
  return 'down';
}

async function probe(name: 'dms' | 'gms', url: string): Promise<void> {
  const started = Date.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS), redirect: 'manual' });
    await res.arrayBuffer().catch(() => undefined);
    const state = stateForStatus(res.status);
    statuses[name] = { name, state, checkedAt: new Date().toISOString(), latencyMs: Date.now() - started, ...(state === 'ok' ? {} : { detail: `answered HTTP ${res.status}` }) };
  } catch (err) {
    const timedOut = (err as Error)?.name === 'TimeoutError' || (err as Error)?.name === 'AbortError';
    statuses[name] = { name, state: 'down', checkedAt: new Date().toISOString(), latencyMs: null, detail: timedOut ? `no answer within ${PROBE_TIMEOUT_MS / 1000}s` : 'connection refused or reset' };
  }
}

async function probeAll(): Promise<void> {
  const jobs: Promise<void>[] = [];
  if (IDP_CONFIG.dms.enabled) jobs.push(probe('dms', `${IDP_CONFIG.dms.apiBaseUrl.replace(/\/+$/, '')}/operations/ready`));
  if (IDP_CONFIG.gms.enabled) jobs.push(probe('gms', `${IDP_CONFIG.gms.apiBase.replace(/\/+$/, '')}/health`));
  await Promise.all(jobs);
}

let timer: NodeJS.Timeout | null = null;

/** Starts the probes (idempotent). The first one runs immediately and is not awaited. */
export function startPeerProbes(): void {
  if (timer) return;
  void probeAll().catch((err) => logger.warn({ err }, '[idp:peers] probe failed'));
  timer = setInterval(() => {
    void probeAll().catch((err) => logger.warn({ err }, '[idp:peers] probe failed'));
  }, PROBE_EVERY_MS);
  timer.unref();
}

export function stopPeerProbes(): void {
  if (timer) clearInterval(timer);
  timer = null;
}

export function getPeerStatuses(): PeerStatus[] {
  return [statuses.dms, statuses.gms];
}
