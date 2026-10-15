/**
 * The readiness collector (ops/readiness.ts): what makes SSO "not ready" (503) versus merely "degraded" (still 200), and what an
 * anonymous caller is allowed to see.
 */
const mockQuery = jest.fn();
const mockPending = jest.fn();
const mockPeers = jest.fn();
const mockSnapshot = jest.fn();
const mockUndecryptable = jest.fn();

jest.mock('../src/db/pool.js', () => ({ pool: { query: (...a: unknown[]) => mockQuery(...a) } }));
jest.mock('../src/db/migrate.js', () => ({ pendingMigrations: () => mockPending() }));
jest.mock('../src/infrastructure/redis.js', () => ({ redisClient: null }));
jest.mock('../src/auth/totp.js', () => ({ undecryptableSecretCount: () => mockUndecryptable() }));
jest.mock('../src/auth/client-role-claims.js', () => ({ dmsRolesBreaker: { snapshot: () => mockSnapshot() } }));
jest.mock('../src/ops/peers.js', () => ({ getPeerStatuses: () => mockPeers() }));
const mockOutbox = jest.fn();
jest.mock('../src/ops/notificationOutbox.js', () => ({ outboxStats: () => mockOutbox() }));
jest.mock('../src/logging/logger.js', () => ({ logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn() } }));
jest.mock('../src/config.js', () => ({ IDP_CONFIG: { dms: { enabled: true }, dmsInternalApiKey: 'k' } }));

import { collectReadiness, httpStatusFor, publicView, resetReadinessCache } from '../src/ops/readiness.js';

function healthyWorld() {
  mockQuery.mockImplementation(async (sql: string) => {
    if (/COUNT\(\*\) AS n FROM idp_signing_keys/.test(sql)) return { rows: [{ n: '1' }] };
    return { rows: [{ '?column?': 1 }] };
  });
  mockPending.mockResolvedValue([]);
  mockPeers.mockReturnValue([
    { name: 'dms', state: 'ok', checkedAt: 'x', latencyMs: 5 },
    { name: 'gms', state: 'ok', checkedAt: 'x', latencyMs: 5 },
  ]);
  mockSnapshot.mockReturnValue({ state: 'closed', consecutiveFailures: 0 });
  mockUndecryptable.mockReturnValue(0);
  mockOutbox.mockResolvedValue({ pending: 0, oldestPendingSeconds: null, abandonedLast7Days: 0 });
}

beforeEach(() => {
  jest.resetAllMocks();
  resetReadinessCache();
  healthyWorld();
});

describe('collectReadiness', () => {
  it('is ready when everything answers', async () => {
    const r = await collectReadiness();
    expect(r.status).toBe('ready');
    expect(httpStatusFor(r)).toBe(200);
    expect(r.checks.redis?.state).toBe('off');
  });

  it('is NOT ready (503) when the database does not answer', async () => {
    mockQuery.mockRejectedValue(new Error('connect ECONNREFUSED 10.0.0.5:5432'));
    const r = await collectReadiness();
    expect(r.status).toBe('not_ready');
    expect(httpStatusFor(r)).toBe(503);
    expect(r.checks.database?.state).toBe('down');
  });

  it('is NOT ready when there is no active signing key', async () => {
    mockQuery.mockImplementation(async (sql: string) => (/idp_signing_keys/.test(sql) ? { rows: [{ n: '0' }] } : { rows: [{}] }));
    const r = await collectReadiness();
    expect(r.status).toBe('not_ready');
    expect(r.checks.signingKeys?.state).toBe('down');
  });

  it('is only degraded (still 200) when a pending migration exists', async () => {
    mockPending.mockResolvedValue(['017_x.sql']);
    const r = await collectReadiness();
    expect(r.status).toBe('degraded');
    expect(httpStatusFor(r)).toBe(200);
    expect(r.checks.schema?.detail).toContain('017_x.sql');
  });

  it('is only degraded when DMS is unreachable, and says the DMS roles are not being applied', async () => {
    mockPeers.mockReturnValue([
      { name: 'dms', state: 'down', checkedAt: 'x', latencyMs: null, detail: 'connection refused or reset' },
      { name: 'gms', state: 'ok', checkedAt: 'x', latencyMs: 5 },
    ]);
    mockSnapshot.mockReturnValue({ state: 'open', consecutiveFailures: 3 });
    const r = await collectReadiness();
    expect(r.status).toBe('degraded');
    expect(httpStatusFor(r)).toBe(200);
    expect(r.checks.dms?.state).toBe('degraded');
    expect(r.checks.dmsRoleLookup?.detail).toContain('omit the DMS roles');
  });

  it('is degraded when a stored authenticator secret cannot be decrypted', async () => {
    mockUndecryptable.mockReturnValue(2);
    const r = await collectReadiness();
    expect(r.status).toBe('degraded');
    expect(r.checks.totpKey?.detail).toContain('TOTP_ENCRYPTION_KEY');
  });

  it('two keys marked active is degraded, not down', async () => {
    mockQuery.mockImplementation(async (sql: string) => (/idp_signing_keys/.test(sql) ? { rows: [{ n: '2' }] } : { rows: [{}] }));
    const r = await collectReadiness();
    expect(r.checks.signingKeys?.state).toBe('degraded');
    expect(r.status).toBe('degraded');
  });

  it('is degraded when a sign-out notification has been waiting a long time, or was given up on', async () => {
    mockOutbox.mockResolvedValue({ pending: 2, oldestPendingSeconds: 1200, abandonedLast7Days: 0 });
    let r = await collectReadiness();
    expect(r.status).toBe('degraded');
    expect(r.checks.notifications?.detail).toContain('still waiting');
    resetReadinessCache();
    mockOutbox.mockResolvedValue({ pending: 0, oldestPendingSeconds: null, abandonedLast7Days: 1 });
    r = await collectReadiness();
    expect(r.checks.notifications?.detail).toContain('given up');
  });

  it('a fresh pending notification is normal (the retry is on its way), not a warning', async () => {
    mockOutbox.mockResolvedValue({ pending: 1, oldestPendingSeconds: 30, abandonedLast7Days: 0 });
    expect((await collectReadiness()).checks.notifications?.state).toBe('ok');
  });

  it('caches for a moment so a probe flood is not a query flood', async () => {
    await collectReadiness();
    const calls = mockQuery.mock.calls.length;
    await collectReadiness();
    expect(mockQuery.mock.calls.length).toBe(calls);
  });
});

describe('publicView', () => {
  it('shows state words only, never a reason', async () => {
    mockQuery.mockRejectedValue(new Error('password authentication failed for user "edams_idp" at db.internal'));
    const view = publicView(await collectReadiness());
    expect(view.db).toBe('unreachable');
    expect(JSON.stringify(view)).not.toMatch(/edams_idp|db\.internal|ECONN|password/i);
    expect(view.checks.database).toBe('down');
  });
});
