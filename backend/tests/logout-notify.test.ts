/**
 * Logout propagation to DMS (auth/logout-notify.ts). This is the only channel that
 * tells DMS an account was disabled / re-roled / signed out, so a single transient
 * failure must not be final, a hung DMS must not hang the admin, and a DMS that
 * stays down must be loud.
 */
const mockQuery = jest.fn();
const mockLogError = jest.fn();
jest.mock('../src/db/pool.js', () => ({ pool: { query: (...a: unknown[]) => mockQuery(...a) } }));
jest.mock('../src/config.js', () => ({
  IDP_CONFIG: {
    issuer: 'http://idp.test',
    dms: { backchannelLogoutUri: 'http://dms.test/api/v1/auth/backchannel-logout' },
    appLogoutTargets: [
      { client_id: 'shop', uri: 'http://shop.test/api/v1/auth/backchannel-logout' },
      { client_id: 'mos', uri: 'http://mos.test/mos/oidc/backchannel-logout' },
    ],
  },
}));
jest.mock('../src/logging/logger.js', () => ({
  logger: { error: (...a: unknown[]) => mockLogError(...a), warn: jest.fn(), info: jest.fn() },
}));

import { exportJWK, generateKeyPair, decodeJwt } from 'jose';
import { DMS_LOGOUT_NOTIFY, appLogoutKind, clientIdOfAppLogoutKind, notifyAppLogout, notifyAppLogouts, notifyDmsLogout, resetDmsLogoutNotifyState } from '../src/auth/logout-notify.js';

const realFetch = global.fetch;
let fetchMock: jest.Mock;

beforeAll(async () => {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = { ...(await exportJWK(privateKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  mockQuery.mockImplementation(async () => ({ rows: [{ jwk }] }));
});

beforeEach(() => {
  resetDmsLogoutNotifyState();
  mockLogError.mockReset();
  DMS_LOGOUT_NOTIFY.attempts = 3;
  DMS_LOGOUT_NOTIFY.backoffMs = 1;
  DMS_LOGOUT_NOTIFY.timeoutMs = 500;
  fetchMock = jest.fn();
  global.fetch = fetchMock as unknown as typeof fetch;
});
afterAll(() => {
  global.fetch = realFetch;
});

const ok = () => ({ ok: true, status: 200 });
const status = (s: number) => ({ ok: false, status: s });

describe('notifyDmsLogout', () => {
  it('posts a signed logout token for the account and reports success', async () => {
    fetchMock.mockResolvedValueOnce(ok());
    expect(await notifyDmsLogout('acct-1')).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = new URLSearchParams(fetchMock.mock.calls[0][1].body as string);
    const claims = decodeJwt(body.get('logout_token')!);
    expect(claims.sub).toBe('acct-1');
    expect(claims.aud).toBe('edams');
    expect(fetchMock.mock.calls[0][1].signal).toBeDefined();
  });

  it('survives a transient failure: connection error then 503 then success', async () => {
    fetchMock.mockRejectedValueOnce(new Error('ECONNREFUSED')).mockResolvedValueOnce(status(503)).mockResolvedValueOnce(ok());
    expect(await notifyDmsLogout('acct-1')).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(mockLogError).not.toHaveBeenCalled();
  });

  it('gives up after the attempt budget and says so loudly', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    expect(await notifyDmsLogout('acct-1')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(mockLogError).toHaveBeenCalledWith(expect.objectContaining({ accountId: 'acct-1', lastFailure: 'ECONNREFUSED' }), expect.stringContaining('ALERT'));
  });

  it('does not retry when DMS answers and refuses the token (400)', async () => {
    fetchMock.mockResolvedValue(status(400));
    expect(await notifyDmsLogout('acct-1')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(mockLogError).toHaveBeenCalled();
  });

  it('retries a 429', async () => {
    fetchMock.mockResolvedValueOnce(status(429)).mockResolvedValueOnce(ok());
    expect(await notifyDmsLogout('acct-1')).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('while DMS is known to be down, later accounts in a burst make a single attempt each', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    await notifyDmsLogout('acct-1');
    fetchMock.mockClear();
    expect(await notifyDmsLogout('acct-2')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('is a no-op (false, no network) when no logout URI is configured or no signing key exists', async () => {
    mockQuery.mockResolvedValueOnce({ rows: [] });
    expect(await notifyDmsLogout('acct-1')).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('the other registered applications (MOS, product apps)', () => {
  beforeEach(() => mockQuery.mockClear()); // keep the implementation, forget the calls of earlier tests
  const queued = () => mockQuery.mock.calls.filter((c) => /INSERT INTO idp_pending_notifications/.test(String(c[0]))).map((c) => c[1] as unknown[]);

  it('each one gets its own token: audience is its client id, subject the account', async () => {
    fetchMock.mockResolvedValue(ok());
    expect(await notifyAppLogout('shop', 'acct-9')).toBe(true);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('http://shop.test/api/v1/auth/backchannel-logout');
    const claims = decodeJwt(new URLSearchParams(init.body as string).get('logout_token')!);
    expect(claims).toMatchObject({ sub: 'acct-9', aud: 'shop', iss: 'http://idp.test' });
    expect(claims.exp! - claims.iat!).toBe(120);
  });

  it('an unregistered application is never contacted', async () => {
    expect(await notifyAppLogout('nobody', 'acct-9')).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('notifyAppLogouts tells all of them side by side and returns the ones that did not answer', async () => {
    fetchMock.mockImplementation(async (url: string) => (String(url).includes('shop.test') ? ok() : status(400)));
    expect(await notifyAppLogouts('acct-9')).toEqual(['mos']);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('a failure is queued under that application\'s own kind, once per application', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    expect(await notifyAppLogouts('acct-9')).toEqual(['shop', 'mos']);
    expect(queued().map((p) => p[0]).sort()).toEqual(['app-logout:mos', 'app-logout:shop']);
    expect(queued().every((p) => p[1] === 'acct-9')).toBe(true);
  });

  it('the retry job asks for no second row (queueOnFailure false)', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    expect(await notifyAppLogout('shop', 'acct-9', { queueOnFailure: false })).toBe(false);
    expect(queued()).toEqual([]);
  });

  it('one application being down does not make DMS (or another application) skip its retries', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED'));
    await notifyAppLogout('shop', 'acct-1');
    fetchMock.mockClear();
    expect(await notifyDmsLogout('acct-2')).toBe(false);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('the kind round-trips to the client id', () => {
    expect(appLogoutKind('shop')).toBe('app-logout:shop');
    expect(clientIdOfAppLogoutKind('app-logout:shop')).toBe('shop');
    expect(clientIdOfAppLogoutKind('dms-logout')).toBeNull();
  });
});
