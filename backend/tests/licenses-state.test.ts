/**
 * The pure licence state function (src/licenses/state.ts; contract section 3). GMS and DMS copy this file, so every boundary is pinned here:
 * the lower edge of each state is inclusive, perpetual never leaves `active`, grace 0 skips grace, warn 0 skips the warning.
 */
import { DAY_MS, computeLicenseState } from '../src/licenses/state.js';

const EXPIRES = Date.UTC(2027, 0, 1, 0, 0, 0, 0);
const at = (offsetMs: number) => EXPIRES + offsetMs;
const lic = (graceDays: number, warnDays: number, expiresAt: number | string | Date | null = EXPIRES) => ({ expiresAt, graceDays, warnDays });

describe('computeLicenseState', () => {
  it('no record is unconfigured and never read-only', () => {
    expect(computeLicenseState(null, EXPIRES)).toEqual({ state: 'unconfigured', daysRemaining: null, expiresAt: null, graceEndsAt: null, readOnly: false });
  });

  describe('grace 14, warn 30', () => {
    const l = lic(14, 30);
    it('active up to the last millisecond before the warning window', () => {
      expect(computeLicenseState(l, at(-30 * DAY_MS - 1)).state).toBe('active');
    });
    it('expiring exactly at expires - warnDays (inclusive)', () => {
      expect(computeLicenseState(l, at(-30 * DAY_MS)).state).toBe('expiring');
    });
    it('expiring up to the last millisecond before expiry', () => {
      expect(computeLicenseState(l, at(-1)).state).toBe('expiring');
    });
    it('grace exactly at expiry (inclusive)', () => {
      expect(computeLicenseState(l, at(0)).state).toBe('grace');
    });
    it('grace up to the last millisecond of the grace period', () => {
      expect(computeLicenseState(l, at(14 * DAY_MS - 1)).state).toBe('grace');
    });
    it('expired exactly at expires + graceDays (inclusive), and read-only', () => {
      const r = computeLicenseState(l, at(14 * DAY_MS));
      expect(r.state).toBe('expired');
      expect(r.readOnly).toBe(true);
    });
    it('only expired is read-only', () => {
      for (const off of [-60 * DAY_MS, -30 * DAY_MS, -1, 0, 14 * DAY_MS - 1]) expect(computeLicenseState(l, at(off)).readOnly).toBe(false);
    });
    it('reports the dates as ISO strings and graceEndsAt = expires + graceDays', () => {
      const r = computeLicenseState(l, at(-10 * DAY_MS));
      expect(r.expiresAt).toBe('2027-01-01T00:00:00.000Z');
      expect(r.graceEndsAt).toBe('2027-01-15T00:00:00.000Z');
    });
  });

  describe('perpetual (expiresAt null)', () => {
    it('is active at any time and has no dates', () => {
      for (const now of [0, EXPIRES, EXPIRES * 10]) {
        expect(computeLicenseState(lic(14, 30, null), now)).toEqual({ state: 'active', daysRemaining: null, expiresAt: null, graceEndsAt: null, readOnly: false });
      }
    });
  });

  describe('grace 0', () => {
    const l = lic(0, 30);
    it('goes expiring -> expired with no grace: the instant of expiry is expired', () => {
      expect(computeLicenseState(l, at(-1)).state).toBe('expiring');
      expect(computeLicenseState(l, at(0)).state).toBe('expired');
      expect(computeLicenseState(l, at(0)).graceEndsAt).toBe('2027-01-01T00:00:00.000Z');
    });
  });

  describe('warn 0', () => {
    const l = lic(14, 0);
    it('goes active -> grace with no warning window', () => {
      expect(computeLicenseState(l, at(-1)).state).toBe('active');
      expect(computeLicenseState(l, at(0)).state).toBe('grace');
    });
  });

  describe('grace 0 and warn 0', () => {
    it('is active until the instant of expiry, then expired', () => {
      const l = lic(0, 0);
      expect(computeLicenseState(l, at(-1)).state).toBe('active');
      expect(computeLicenseState(l, at(0)).state).toBe('expired');
    });
  });

  describe('maximum windows (365 / 365)', () => {
    const l = lic(365, 365);
    it('hold their boundaries', () => {
      expect(computeLicenseState(l, at(-365 * DAY_MS - 1)).state).toBe('active');
      expect(computeLicenseState(l, at(-365 * DAY_MS)).state).toBe('expiring');
      expect(computeLicenseState(l, at(365 * DAY_MS - 1)).state).toBe('grace');
      expect(computeLicenseState(l, at(365 * DAY_MS)).state).toBe('expired');
    });
  });

  describe('daysRemaining (whole days, truncated toward zero)', () => {
    const l = lic(14, 30);
    it('counts whole days to expiry', () => {
      expect(computeLicenseState(l, at(-10 * DAY_MS)).daysRemaining).toBe(10);
      expect(computeLicenseState(l, at(-(2 * DAY_MS + DAY_MS - 1))).daysRemaining).toBe(2);
      expect(computeLicenseState(l, at(-1)).daysRemaining).toBe(0);
    });
    it('is 0 (never -0) at and just after expiry, then negative', () => {
      const exactly = computeLicenseState(l, at(0)).daysRemaining;
      expect(Object.is(exactly, 0)).toBe(true);
      expect(Object.is(computeLicenseState(l, at(1)).daysRemaining, 0)).toBe(true);
      expect(computeLicenseState(l, at(3 * DAY_MS)).daysRemaining).toBe(-3);
      expect(computeLicenseState(l, at(3 * DAY_MS + 5)).daysRemaining).toBe(-3);
    });
  });

  describe('input forms', () => {
    it('accepts an ISO string, a Date and epoch milliseconds for both the date and the clock', () => {
      const iso = new Date(EXPIRES).toISOString();
      const now = new Date(EXPIRES + DAY_MS);
      expect(computeLicenseState(lic(14, 30, iso), now).state).toBe('grace');
      expect(computeLicenseState(lic(14, 30, new Date(EXPIRES)), EXPIRES + DAY_MS).state).toBe('grace');
    });
    it('an unreadable date never enforces anything', () => {
      const r = computeLicenseState(lic(14, 30, 'not a date'), EXPIRES);
      expect(r.state).toBe('unknown');
      expect(r.readOnly).toBe(false);
    });
  });
});
