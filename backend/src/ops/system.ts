/**
 * The System page's data: everything an administrator would want to know about how this SSO process is doing, in one call.
 * Nothing here is a secret (no keys, no passwords, no connection strings), and it is only served to a signed-in console administrator.
 */
import fs from 'node:fs';
import path from 'node:path';
import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { redisClient } from '../infrastructure/redis.js';
import { dmsRolesBreaker } from '../auth/client-role-claims.js';
import { isAdEnabled } from '../auth/ldap.service.js';
import { passwordGate } from '../auth/password.js';
import { getBool } from '../settings/store.js';
import { listJobs } from './jobs.js';
import { collectReadiness } from './readiness.js';
import { getPeerStatuses } from './peers.js';
import { outboxStats } from './notificationOutbox.js';

interface SupervisorInfo {
  supervised: boolean;
  supervisorPid: number | null;
  restarts: number;
  watchdogKills: number;
  lastExit: { code: number | null; signal: string | null; at: string; ranSeconds: number; reason: string } | null;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** Reads the state file deploy/supervise.cjs keeps next to the logs. Absent or stale means nothing is supervising this process. */
export function readSupervisor(cwd = process.cwd()): SupervisorInfo {
  const none: SupervisorInfo = { supervised: false, supervisorPid: null, restarts: 0, watchdogKills: 0, lastExit: null };
  try {
    const state = JSON.parse(fs.readFileSync(path.join(cwd, 'logs', 'supervisor-sso-backend.json'), 'utf8')) as {
      supervisorPid?: number; childPid?: number | null; restarts?: number; watchdogKills?: number; lastExit?: SupervisorInfo['lastExit'];
    };
    // The supervisor's own child is this process; a state file whose child is another pid belongs to a previous run.
    if (!state.supervisorPid || !pidAlive(state.supervisorPid) || (state.childPid && state.childPid !== process.pid)) return none;
    return { supervised: true, supervisorPid: state.supervisorPid, restarts: state.restarts ?? 0, watchdogKills: state.watchdogKills ?? 0, lastExit: state.lastExit ?? null };
  } catch {
    return none;
  }
}

function packageVersion(): string {
  try {
    return (JSON.parse(fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')) as { version?: string }).version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}

export async function collectSystem() {
  const readiness = await collectReadiness();
  const mem = process.memoryUsage();
  const supervisor = readSupervisor();
  return {
    readiness,
    peers: getPeerStatuses(),
    breakers: [dmsRolesBreaker.snapshot()],
    jobs: listJobs(),
    // Password checks running, waiting and turned away since start (infrastructure/workGate.ts): a rising `refused` means sign-in is being flooded.
    passwordChecks: passwordGate.stats(),
    notifications: await outboxStats().catch(() => ({ pending: 0, oldestPendingSeconds: null, abandonedLast7Days: 0 })),
    database: { poolMax: IDP_CONFIG.db.poolMax, poolTotal: pool.totalCount, poolIdle: pool.idleCount, poolWaiting: pool.waitingCount },
    process: {
      pid: process.pid,
      node: process.version,
      version: packageVersion(),
      environment: IDP_CONFIG.env,
      startedAt: readiness.startedAt,
      uptimeSeconds: readiness.uptimeSeconds,
      rssMb: Math.round(mem.rss / 1048576),
      heapUsedMb: Math.round(mem.heapUsed / 1048576),
    },
    supervisor,
    // Production and the mirror must run supervised (deploy/supervise.cjs); dev is run by nodemon.
    supervisionExpected: IDP_CONFIG.isProd || IDP_CONFIG.env === 'mirror',
    config: {
      issuer: IDP_CONFIG.issuer,
      publicBasePath: IDP_CONFIG.publicBasePath || '/',
      trustProxyHops: IDP_CONFIG.trustProxyHops,
      activeDirectory: isAdEnabled() ? 'enabled' : 'not configured',
      gmsBridge: IDP_CONFIG.gms.enabled,
      dms: IDP_CONFIG.dms.enabled,
      redis: redisClient ? 'configured' : 'not configured',
      lockoutEnabled: getBool('lockout.enabled'),
      adminTwoFactorRequired: getBool('mfa.requireForAdmins'),
    },
  };
}
