/**
 * The audit-chain endpoints of the console API: GET /audit/verify and POST /audit/chain-acknowledgements (api/v1/admin.router.ts and
 * admin-mutations.router.ts), driven over real HTTP. Admin authentication, the platform-administrator check and the chain itself are mocked
 * (the chain's own behaviour is proved in audit-chain.test.ts); what is proved here is who may do what and what the browser is sent.
 *
 * Proves: an ordinary administrator is refused with 403 and nothing is recorded; a missing or wrong CSRF token is refused; the platform
 * administrator can acknowledge; the verifier's server-side `pin` never reaches the browser; and each refusal from the chain
 * (not reported, already acknowledged, kind that cannot be acknowledged, reason too short) arrives as the right status and code.
 */
import type { AddressInfo } from 'node:net';
import http from 'node:http';

const state = { platform: false };
const mockSession = { accountId: 'jest-chain-admin', name: 'Jest Admin', email: 'jest-chain@example.invalid', groups: [] as string[], createdAt: 0 };
const mockAck = jest.fn();
const mockVerify = jest.fn();

jest.mock('../src/admin/requireAdmin.js', () => {
  const gate = () => (req: { adminSession?: unknown }, _res: unknown, next: () => void) => {
    req.adminSession = mockSession;
    next();
  };
  return { requireAdminJson: gate, getPortalSessionFromRequest: jest.fn() };
});
jest.mock('../src/auth/platform-admin.js', () => ({
  ...jest.requireActual('../src/auth/platform-admin.js'),
  isPlatformAdminSession: async () => state.platform,
}));
jest.mock('../src/admin/audit.js', () => {
  class ChainAcknowledgementError extends Error {
    constructor(
      public readonly status: number,
      public readonly code: string,
      message: string,
    ) {
      super(message);
    }
  }
  return {
    ChainAcknowledgementError,
    MIN_ACK_REASON_LENGTH: 20,
    writeAudit: jest.fn(async () => undefined),
    recentAudit: jest.fn(),
    countAuditRows: jest.fn(),
    verifyAuditChain: (...a: unknown[]) => mockVerify(...a),
    acknowledgeChainBreak: (...a: unknown[]) => mockAck(...a),
  };
});

import express from 'express';
import { ADMIN_API_CSRF_COOKIE, adminApiRouter } from '../src/api/v1/admin.router.js';
import { adminMutationsRouter } from '../src/api/v1/admin-mutations.router.js';
import { ChainAcknowledgementError } from '../src/admin/audit.js';
import { lastAuditChainState, resetAuditChainState } from '../src/ops/auditChain.js';

const CSRF = 'csrf-token-for-jest-chain';
const REASON = 'Restored from the 2026-09-02 backup; the gap is known and was reviewed.';

const withPin = (acknowledged = false) => ({
  valid: acknowledged,
  checked: 5,
  legacyCount: 0,
  breaks: [
    {
      sequenceNumber: '3',
      kind: 'hash',
      message: 'Entry 3 was modified',
      acknowledgeable: true,
      pin: { entryHash: 'secret-entry-hash', previousHash: 'secret-prev', fingerprint: 'secret-fingerprint' },
      ...(acknowledged ? { acknowledged: { by: 'platform', at: '2026-10-11T00:00:00.000Z', reason: REASON } } : {}),
    },
  ],
  openBreaks: acknowledged ? 0 : 1,
  acknowledgedBreaks: acknowledged ? 1 : 0,
  truncated: false,
  brokenAtSequence: acknowledged ? undefined : '3',
  message: 'x',
});

let server: http.Server;
let base = '';

async function call(method: 'GET' | 'POST', path: string, body?: Record<string, unknown>, csrf: string | null = CSRF) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { 'content-type': 'application/json', ...(csrf ? { cookie: `${ADMIN_API_CSRF_COOKIE}=${csrf}` } : {}) },
    body: method === 'POST' ? JSON.stringify({ ...(body ?? {}), csrf: csrf ?? 'none' }) : undefined,
  });
  return { status: res.status, json: (await res.json()) as any };
}

beforeAll(async () => {
  const app = express();
  app.use('/api/v1/admin', adminApiRouter());
  app.use('/api/v1/admin', adminMutationsRouter({} as never));
  server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/v1/admin`;
});

beforeEach(() => {
  state.platform = false;
  mockAck.mockReset();
  mockVerify.mockReset();
  resetAuditChainState();
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

describe('GET /audit/verify', () => {
  it('lists the breaks, tells the page whether the viewer may acknowledge, and never sends the pin', async () => {
    mockVerify.mockResolvedValue(withPin(false));
    const asAdmin = await call('GET', '/audit/verify');
    expect(asAdmin.status).toBe(200);
    expect(asAdmin.json.data.viewerIsPlatformAdmin).toBe(false);
    expect(asAdmin.json.data.minReasonLength).toBe(20);
    expect(asAdmin.json.data.chain.breaks[0]).toMatchObject({ sequenceNumber: '3', kind: 'hash', acknowledgeable: true });
    expect(JSON.stringify(asAdmin.json)).not.toMatch(/secret-entry-hash|secret-prev|secret-fingerprint|"pin"/);

    state.platform = true;
    expect((await call('GET', '/audit/verify')).json.data.viewerIsPlatformAdmin).toBe(true);
  });

  it('remembers the outcome, so the health check reports it without anyone opening the page', async () => {
    mockVerify.mockResolvedValue(withPin(false));
    await call('GET', '/audit/verify');
    expect(lastAuditChainState()).toMatchObject({ valid: false, openBreaks: 1, firstOpenBreak: '3' });
  });
});

describe('POST /audit/chain-acknowledgements', () => {
  const body = { sequenceNumber: '3', kind: 'hash', reason: REASON };

  it('refuses an ordinary administrator and records nothing', async () => {
    const r = await call('POST', '/audit/chain-acknowledgements', body);
    expect(r.status).toBe(403);
    expect(r.json.error.code).toBe('ERR-PLATFORM-ADMIN-ONLY');
    expect(mockAck).not.toHaveBeenCalled();
  });

  it('refuses a request without a valid CSRF token, even from the platform administrator', async () => {
    state.platform = true;
    const none = await call('POST', '/audit/chain-acknowledgements', body, null);
    expect(none.status).toBe(403);
    expect(none.json.error.code).toBe('ERR-INVALID-CSRF');
    const res = await fetch(`${base}/audit/chain-acknowledgements`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `${ADMIN_API_CSRF_COOKIE}=${CSRF}` },
      body: JSON.stringify({ ...body, csrf: 'a-different-token' }),
    });
    expect(res.status).toBe(403);
    expect(mockAck).not.toHaveBeenCalled();
  });

  it('lets the platform administrator acknowledge, passes exactly what was sent, remembers the new verdict, and strips the pin', async () => {
    state.platform = true;
    mockAck.mockResolvedValue(withPin(true));
    const r = await call('POST', '/audit/chain-acknowledgements', body);
    expect(r.status).toBe(200);
    expect(mockAck).toHaveBeenCalledTimes(1);
    expect(mockAck.mock.calls[0][1]).toBe(mockSession.email);
    expect(mockAck.mock.calls[0][2]).toEqual({ sequenceNumber: '3', kind: 'hash', reason: REASON });
    expect(r.json.data.chain.valid).toBe(true);
    expect(r.json.data.chain.breaks[0].acknowledged.reason).toBe(REASON);
    expect(JSON.stringify(r.json)).not.toMatch(/secret-entry-hash|secret-fingerprint|"pin"/);
    expect(lastAuditChainState()).toMatchObject({ valid: true, openBreaks: 0, acknowledgedBreaks: 1 });
  });

  it.each([
    [404, 'ERR-CHAIN-BREAK-NOT-FOUND'],
    [409, 'ERR-CHAIN-BREAK-ACKNOWLEDGED'],
    [422, 'ERR-CHAIN-BREAK-NOT-ACKNOWLEDGEABLE'],
    [422, 'ERR-VALIDATION-FAILED'],
  ])('passes the chain refusal through as HTTP %i %s', async (status, code) => {
    state.platform = true;
    mockAck.mockRejectedValue(new ChainAcknowledgementError(status as 404 | 409 | 422, code, 'refused'));
    const r = await call('POST', '/audit/chain-acknowledgements', body);
    expect(r.status).toBe(status);
    expect(r.json.error.code).toBe(code);
  });

  it('an unexpected failure is a 500, not a recorded acknowledgement', async () => {
    state.platform = true;
    mockAck.mockRejectedValue(new Error('database exploded'));
    // The app's own error handler (main.ts) shapes the body; here only the status matters, and Express's default answers HTML.
    const res = await fetch(`${base}/audit/chain-acknowledgements`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `${ADMIN_API_CSRF_COOKIE}=${CSRF}` },
      body: JSON.stringify({ ...body, csrf: CSRF }),
    });
    expect(res.status).toBe(500);
    expect(lastAuditChainState()).toBeNull();
  });
});
