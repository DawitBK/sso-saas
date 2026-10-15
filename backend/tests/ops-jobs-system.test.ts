/**
 * Background-job status (ops/jobs.ts) and the supervisor detection behind the System page (ops/system.ts readSupervisor).
 */
jest.mock('../src/config.js', () => ({ IDP_CONFIG: { env: 'test', isProd: false, db: { poolMax: 5 }, issuer: 'http://x', publicBasePath: '', trustProxyHops: 1, gms: { enabled: false }, dms: { enabled: false } } }));
jest.mock('../src/db/pool.js', () => ({ pool: { totalCount: 0, idleCount: 0, waitingCount: 0, query: jest.fn() } }));
jest.mock('../src/infrastructure/redis.js', () => ({ redisClient: null }));
jest.mock('../src/auth/client-role-claims.js', () => ({ dmsRolesBreaker: { snapshot: () => ({ name: 'dms-roles', state: 'closed' }) } }));
jest.mock('../src/auth/ldap.service.js', () => ({ isAdEnabled: () => false }));
jest.mock('../src/settings/store.js', () => ({ getBool: () => false }));
jest.mock('../src/auth/password.js', () => ({ passwordGate: { stats: () => ({ max: 3, running: 0, waiting: 0, refused: 0, completed: 0 }) } }));
jest.mock('../src/ops/readiness.js', () => ({ collectReadiness: jest.fn() }));
jest.mock('../src/ops/peers.js', () => ({ getPeerStatuses: () => [] }));
jest.mock('../src/ops/notificationOutbox.js', () => ({ outboxStats: async () => ({ pending: 0, oldestPendingSeconds: null, abandonedLast7Days: 0 }) }));

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { declareJob, listJobs, resetJobs, trackJob } from '../src/ops/jobs.js';
import { readSupervisor } from '../src/ops/system.js';

beforeEach(() => resetJobs());

describe('job status', () => {
  it('records a success', async () => {
    declareJob('purge', 3600);
    await trackJob('purge', async () => undefined);
    const [job] = listJobs();
    expect(job).toMatchObject({ name: 'purge', everySeconds: 3600, runs: 1, failures: 0, lastError: null });
    expect(job?.lastOkAt).not.toBeNull();
  });

  it('records a failure with its class only, never the message (a Postgres message names host, database and role)', async () => {
    declareJob('purge', 3600);
    const err = Object.assign(new Error('password authentication failed for user "edams_idp" at db.internal'), { code: '28P01' });
    await expect(trackJob('purge', async () => { throw err; })).rejects.toBe(err);
    const [job] = listJobs();
    expect(job).toMatchObject({ runs: 1, failures: 1, lastError: 'Error (28P01)' });
    expect(job?.lastOkAt).toBeNull();
  });

  it('a later success clears the error and keeps the failure count', async () => {
    declareJob('ad-resync', 1800);
    await trackJob('ad-resync', async () => { throw new Error('x'); }).catch(() => undefined);
    await trackJob('ad-resync', async () => undefined);
    expect(listJobs()[0]).toMatchObject({ runs: 2, failures: 1, lastError: null });
  });

  it('flags a job that has not started for more than twice its interval', async () => {
    declareJob('purge', 60);
    await trackJob('purge', async () => undefined);
    expect(listJobs()[0]?.overdue).toBe(false);
    expect(listJobs(Date.now() + 121_000)[0]?.overdue).toBe(true);
    declareJob('never-run', 60);
    expect(listJobs().find((j) => j.name === 'never-run')?.overdue).toBe(false);
  });

  it('refuses an undeclared job', async () => {
    await expect(trackJob('nope', async () => undefined)).rejects.toThrow(/not declared/);
  });
});

describe('readSupervisor', () => {
  function withState(state: unknown): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sso-sup-'));
    fs.mkdirSync(path.join(dir, 'logs'));
    if (state !== null) fs.writeFileSync(path.join(dir, 'logs', 'supervisor-sso-backend.json'), JSON.stringify(state));
    return dir;
  }

  it('says unsupervised when there is no state file', () => {
    expect(readSupervisor(withState(null)).supervised).toBe(false);
  });

  it('reads a live supervisor whose child is this process', () => {
    const info = readSupervisor(withState({ supervisorPid: process.pid, childPid: process.pid, restarts: 3, watchdogKills: 1, lastExit: { code: 1, signal: null, at: 'x', ranSeconds: 5, reason: 'exit' } }));
    expect(info).toMatchObject({ supervised: true, supervisorPid: process.pid, restarts: 3, watchdogKills: 1 });
    expect(info.lastExit?.reason).toBe('exit');
  });

  it('ignores a state file left by a previous run (another child pid)', () => {
    expect(readSupervisor(withState({ supervisorPid: process.pid, childPid: process.pid + 99_999 })).supervised).toBe(false);
  });

  it('ignores a state file whose supervisor is dead', () => {
    expect(readSupervisor(withState({ supervisorPid: 2_147_000_000, childPid: process.pid })).supervised).toBe(false);
  });

  it('survives a corrupt state file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sso-sup-'));
    fs.mkdirSync(path.join(dir, 'logs'));
    fs.writeFileSync(path.join(dir, 'logs', 'supervisor-sso-backend.json'), '{not json');
    expect(readSupervisor(dir).supervised).toBe(false);
  });
});
