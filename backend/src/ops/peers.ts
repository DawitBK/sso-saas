/**
 * Background reachability probes for the systems SSO talks to: DMS and GMS (always, when switched on) and every other application that was given a
 * health address (MOS_HEALTH_URL, a `health_uri` in PRODUCT_CLIENTS_JSON; config.ts's appHealthTargets).
 *
 * SSO can sign people in without any of them, so none is a reason to refuse traffic; but an operator needs to see at a glance
 * that "DMS roles are not being applied because DMS is down" or that "Retail OS is not answering, so its people cannot get in". The probes run on a
 * timer and the result is cached, so reading readiness (ops/readiness.ts) never waits on another system and a flood of health requests cannot become
 * a flood of calls into the applications.
 *
 * DMS: GET <DMS_API_BASE_URL>/operations/ready (unauthenticated, 503 when its database, Redis or workers have failed).
 * GMS: GET <GMS_API_BASE>/health (liveness).
 * Any other application: GET its health address; 2xx is fine, 503 is "answering but unwell".
 */
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';

export type PeerState = 'ok' | 'degraded' | 'down' | 'off';

export interface PeerStatus {
  /** `dms`, `gms`, or the application's client id. */
  name: string;
  /** What the console calls it. */
  label: string;
  state: PeerState;
  checkedAt: string | null;
  latencyMs: number | null;
  /** Operator-facing reason; never returned to an anonymous caller. */
  detail?: string;
}

const PROBE_EVERY_MS = 30_000;
const PROBE_TIMEOUT_MS = 3_000;

interface Target {
  name: string;
  label: string;
  /** Null when the system is switched off. */
  url: string | null;
  offDetail: string;
}

/** The systems to probe, in the order the console lists them. Built from the live configuration so a test can change it. */
export function peerTargets(): Target[] {
  return [
    {
      name: 'dms',
      label: 'DMS',
      url: IDP_CONFIG.dms.enabled ? `${IDP_CONFIG.dms.apiBaseUrl.replace(/\/+$/, '')}/operations/ready` : null,
      offDetail: 'DMS_ENABLED is false',
    },
    {
      name: 'gms',
      label: 'GMS',
      url: IDP_CONFIG.gms.enabled ? `${IDP_CONFIG.gms.apiBase.replace(/\/+$/, '')}/health` : null,
      offDetail: 'GMS_BRIDGE_ENABLED is false',
    },
    ...IDP_CONFIG.appHealthTargets.map((t) => ({ name: t.client_id, label: t.label, url: t.uri, offDetail: 'no health address is set' })),
  ];
}

const statuses = new Map<string, PeerStatus>();

function initialStatus(t: Target): PeerStatus {
  return { name: t.name, label: t.label, state: t.url ? 'down' : 'off', checkedAt: null, latencyMs: null, detail: t.url ? 'not probed yet' : t.offDetail };
}

/** Maps an HTTP answer to a state: 2xx fine; 503 means "answering but unwell"; anything else is down. */
export function stateForStatus(status: number): PeerState {
  if (status >= 200 && status < 300) return 'ok';
  if (status === 503) return 'degraded';
  return 'down';
}

async function probe(t: Target & { url: string }): Promise<void> {
  const started = Date.now();
  const base = { name: t.name, label: t.label };
  try {
    const res = await fetch(t.url, { signal: AbortSignal.timeout(PROBE_TIMEOUT_MS), redirect: 'manual' });
    await res.arrayBuffer().catch(() => undefined);
    const state = stateForStatus(res.status);
    statuses.set(t.name, { ...base, state, checkedAt: new Date().toISOString(), latencyMs: Date.now() - started, ...(state === 'ok' ? {} : { detail: `answered HTTP ${res.status}` }) });
  } catch (err) {
    const timedOut = (err as Error)?.name === 'TimeoutError' || (err as Error)?.name === 'AbortError';
    statuses.set(t.name, { ...base, state: 'down', checkedAt: new Date().toISOString(), latencyMs: null, detail: timedOut ? `no answer within ${PROBE_TIMEOUT_MS / 1000}s` : 'connection refused or reset' });
  }
}

async function probeAll(): Promise<void> {
  const jobs: Promise<void>[] = [];
  for (const t of peerTargets()) {
    if (t.url) jobs.push(probe({ ...t, url: t.url }));
  }
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

/** Every system that is probed or switched off, in console order. Not yet probed means `down` until the first answer. */
export function getPeerStatuses(): PeerStatus[] {
  return peerTargets().map((t) => statuses.get(t.name) ?? initialStatus(t));
}
