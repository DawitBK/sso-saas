/**
 * The reachability probes (ops/peers.ts): DMS and GMS as before, plus every application that was given a health address.
 */
const mockConfig = {
  dms: { enabled: true, apiBaseUrl: 'http://dms:7100/api/v1/' },
  gms: { enabled: false, apiBase: 'http://gms:7200/api/v1' },
  appHealthTargets: [
    { client_id: 'retail-os', label: 'Retail OS', uri: 'http://retail:16101/health/ready' },
    { client_id: 'mos', label: 'MOS', uri: 'http://mos:8069/web/health' },
  ],
};
jest.mock('../src/config.js', () => ({ IDP_CONFIG: mockConfig }));
jest.mock('../src/logging/logger.js', () => ({ logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn(), debug: jest.fn() } }));

import { getPeerStatuses, peerTargets, startPeerProbes, stateForStatus, stopPeerProbes } from '../src/ops/peers.js';

afterEach(() => {
  stopPeerProbes();
  jest.restoreAllMocks();
});

describe('peerTargets', () => {
  it('lists DMS, GMS and each application with a health address, in that order, and leaves a switched-off system without an address', () => {
    const t = peerTargets();
    expect(t.map((x) => x.name)).toEqual(['dms', 'gms', 'retail-os', 'mos']);
    expect(t.map((x) => x.label)).toEqual(['DMS', 'GMS', 'Retail OS', 'MOS']);
    expect(t[0]?.url).toBe('http://dms:7100/api/v1/operations/ready');
    expect(t[1]?.url).toBeNull();
    expect(t[2]?.url).toBe('http://retail:16101/health/ready');
  });
});

describe('stateForStatus', () => {
  it('maps an answer to a state', () => {
    expect(stateForStatus(200)).toBe('ok');
    expect(stateForStatus(503)).toBe('degraded');
    expect(stateForStatus(500)).toBe('down');
    expect(stateForStatus(404)).toBe('down');
  });
});

describe('probing', () => {
  it('starts everything that is switched on as down (not probed yet) and everything else as off', () => {
    const s = getPeerStatuses();
    expect(s.find((p) => p.name === 'gms')).toMatchObject({ state: 'off', detail: 'GMS_BRIDGE_ENABLED is false' });
    expect(s.find((p) => p.name === 'retail-os')).toMatchObject({ state: 'down', detail: 'not probed yet' });
  });

  it('records what each application answered, and a refused connection as down', async () => {
    jest.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const url = String(input);
      if (url.includes('retail')) return new Response('ok', { status: 200 });
      if (url.includes('dms')) return new Response('unwell', { status: 503 });
      throw new TypeError('fetch failed');
    });
    startPeerProbes();
    await new Promise((r) => setTimeout(r, 50));
    const by = Object.fromEntries(getPeerStatuses().map((p) => [p.name, p]));
    expect(by.dms).toMatchObject({ state: 'degraded', detail: 'answered HTTP 503' });
    expect(by['retail-os']).toMatchObject({ state: 'ok', label: 'Retail OS' });
    expect(by.mos).toMatchObject({ state: 'down', detail: 'connection refused or reset' });
    expect(by.gms?.state).toBe('off');
  });
});
