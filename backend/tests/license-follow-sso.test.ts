import { followSso } from '../src/licenses/follow.js';
import type { LicenseRecord } from '../src/licenses/repository.js';

const base = (system: LicenseRecord['system'], over: Partial<LicenseRecord> = {}): LicenseRecord => ({
  system,
  customer: 'Example',
  expiresAt: null,
  graceDays: 14,
  warnDays: 30,
  maxUsers: null,
  modules: null,
  modes: ['sso'],
  notes: '',
  version: 100,
  createdAt: '2026-10-01T00:00:00.000Z',
  updatedAt: '2026-10-01T00:00:00.000Z',
  updatedBy: 'test',
  ...over,
});

describe('followSso (owner decision 2026-10-21: clients stop when SSO stops)', () => {
  it('SSO itself is never changed', () => {
    const sso = base('sso', { expiresAt: '2027-01-01T23:59:59.999Z' });
    expect(followSso(sso, sso, 500)).toBe(sso);
  });

  it('a client that never expires takes SSO expiry, grace and warning days', () => {
    const out = followSso(base('dms'), base('sso', { expiresAt: '2027-01-01T23:59:59.999Z', graceDays: 3, warnDays: 9, version: 300, updatedAt: '2026-10-21T10:00:00.000Z' }), 300);
    expect(out).toMatchObject({ expiresAt: '2027-01-01T23:59:59.999Z', graceDays: 3, warnDays: 9, version: 300, updatedAt: '2026-10-21T10:00:00.000Z' });
  });

  it('a client whose own date is later takes SSO date; one whose own date is earlier keeps it', () => {
    const sso = base('sso', { expiresAt: '2027-06-30T23:59:59.999Z', graceDays: 5 });
    expect(followSso(base('gms', { expiresAt: '2030-01-01T23:59:59.999Z' }), sso, 50).expiresAt).toBe('2027-06-30T23:59:59.999Z');
    const own = base('gms', { expiresAt: '2027-01-01T23:59:59.999Z', graceDays: 14 });
    const kept = followSso(own, sso, 50);
    expect(kept.expiresAt).toBe('2027-01-01T23:59:59.999Z');
    expect(kept.graceDays).toBe(14);
  });

  it("SSO's grace days never carry a client past the end of its own grace period", () => {
    const sso = base('sso', { expiresAt: '2027-03-30T23:59:59.999Z', graceDays: 30 });
    const out = followSso(base('gms', { expiresAt: '2027-03-31T23:59:59.999Z', graceDays: 3 }), sso, 50);
    expect(out.expiresAt).toBe('2027-03-30T23:59:59.999Z');
    expect(out.graceDays).toBe(4);
    expect(followSso(base('gms'), sso, 50).graceDays).toBe(30); // a perpetual client has no own hard stop
  });

  it('a licence that may also run standalone is not tied to SSO and is served unchanged', () => {
    const sso = base('sso', { expiresAt: '2027-01-01T23:59:59.999Z' });
    const own = base('dms', { expiresAt: '2030-01-01T23:59:59.999Z', modes: ['sso', 'standalone'], version: 100 });
    expect(followSso(own, sso, 50)).toBe(own);
    expect(followSso(base('dms', { modes: ['sso', 'standalone'] }), sso, 50).expiresAt).toBeNull();
  });

  it('an SSO licence that never expires, or no SSO licence, changes nothing but may raise the version', () => {
    const own = base('gms', { expiresAt: '2030-01-01T23:59:59.999Z', version: 100 });
    expect(followSso(own, base('sso'), 50)).toBe(own);
    expect(followSso(own, null, 50)).toBe(own);
    expect(followSso(own, null, 700)).toMatchObject({ expiresAt: '2030-01-01T23:59:59.999Z', version: 700 });
  });

  it('the served version is never lower than SSO highest ever, so every SSO change reaches the clients', () => {
    const sso = base('sso', { expiresAt: '2027-01-01T23:59:59.999Z', version: 900 });
    expect(followSso(base('dms', { version: 100 }), sso, 900).version).toBe(900);
    expect(followSso(base('dms', { version: 1200 }), sso, 900).version).toBe(1200);
  });
});
