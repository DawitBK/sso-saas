/** Licence input validation (src/licenses/validation.ts): real dates, 0..365 day windows, seats >= 1, catalogue module keys, explicit expiry on create. */
import { DAY_MS } from '../src/licenses/state.js';
import { extendedExpiry, parseExpiry, validateExtendInput, validateLicenseInput } from '../src/licenses/validation.js';
import type { LicenseRecord } from '../src/licenses/repository.js';

const existing = (over: Partial<LicenseRecord> = {}): LicenseRecord => ({
  system: 'gms', customer: 'Example Corp', expiresAt: '2027-01-01T00:00:00.000Z', graceDays: 14, warnDays: 30, maxUsers: 50, modules: ['visits'],
  notes: '', version: 3, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', updatedBy: 'platform', ...over,
});

const fieldsOf = (r: ReturnType<typeof validateLicenseInput>) => (r.ok ? [] : r.details.map((d) => d.field));

describe('parseExpiry', () => {
  it('a date-only value means the end of that day, UTC', () => {
    expect(parseExpiry('2027-01-01')).toEqual({ ok: true, iso: '2027-01-01T23:59:59.999Z' });
  });
  it('a full date-time with a zone is taken as written', () => {
    expect(parseExpiry('2027-01-01T00:00:00Z')).toEqual({ ok: true, iso: '2027-01-01T00:00:00.000Z' });
    expect(parseExpiry('2027-01-01T03:00:00+03:00')).toEqual({ ok: true, iso: '2027-01-01T00:00:00.000Z' });
  });
  it.each(['2027-02-30', '2027-13-01', '2027-00-10', 'tomorrow', '', '2027-01-01T00:00:00', '01/01/2027', '1999-12-31', '2101-01-01', '2027-02-30T00:00:00Z'])(
    'refuses %p',
    (v) => expect(parseExpiry(v).ok).toBe(false),
  );
  it('refuses a non-string', () => {
    expect(parseExpiry(20270101).ok).toBe(false);
    expect(parseExpiry(null).ok).toBe(false);
  });
  it('accepts 29 February only in a leap year', () => {
    expect(parseExpiry('2028-02-29').ok).toBe(true);
    expect(parseExpiry('2027-02-29').ok).toBe(false);
  });
});

describe('validateLicenseInput on a new licence', () => {
  it('requires the customer and an explicit expiry', () => {
    expect(fieldsOf(validateLicenseInput('gms', {}, null)).sort()).toEqual(['customer', 'expiresAt']);
  });
  it('null expiry means "never" and applies the defaults (grace 14, warn 30, no limit, all modules)', () => {
    const r = validateLicenseInput('gms', { customer: ' Example Corp ', expiresAt: null }, null);
    expect(r).toEqual({ ok: true, value: { customer: 'Example Corp', expiresAt: null, graceDays: 14, warnDays: 30, maxUsers: null, modules: null, notes: '' } });
  });
  it('grace and warn accept 0 and 365, refuse -1, 366, fractions and strings', () => {
    expect(validateLicenseInput('gms', { customer: 'x', expiresAt: null, graceDays: 0, warnDays: 365 }, null).ok).toBe(true);
    for (const bad of [-1, 366, 1.5, '14', null]) {
      expect(fieldsOf(validateLicenseInput('gms', { customer: 'x', expiresAt: null, graceDays: bad }, null))).toEqual(['graceDays']);
      expect(fieldsOf(validateLicenseInput('gms', { customer: 'x', expiresAt: null, warnDays: bad }, null))).toEqual(['warnDays']);
    }
  });
  it('max users is null (unlimited) or at least 1', () => {
    expect(validateLicenseInput('gms', { customer: 'x', expiresAt: null, maxUsers: 1 }, null).ok).toBe(true);
    for (const bad of [0, -5, 2.5, '10']) expect(fieldsOf(validateLicenseInput('gms', { customer: 'x', expiresAt: null, maxUsers: bad }, null))).toEqual(['maxUsers']);
  });
  it('module keys must be in the catalogue; the result is in catalogue order without duplicates', () => {
    const ok = validateLicenseInput('gms', { customer: 'x', expiresAt: null, modules: ['ocr', 'visits', 'visits'] }, null);
    expect(ok.ok && ok.value.modules).toEqual(['visits', 'ocr']);
    expect(fieldsOf(validateLicenseInput('gms', { customer: 'x', expiresAt: null, modules: ['visits', 'letters'] }, null))).toEqual(['modules']);
    expect(validateLicenseInput('dms', { customer: 'x', expiresAt: null, modules: ['letters', 'legal_hold'] }, null).ok).toBe(true);
    expect(fieldsOf(validateLicenseInput('gms', { customer: 'x', expiresAt: null, modules: 'visits' }, null))).toEqual(['modules']);
  });
  it('an empty list switches every gateable module off (it is not the same as null)', () => {
    const r = validateLicenseInput('gms', { customer: 'x', expiresAt: null, modules: [] }, null);
    expect(r.ok && r.value.modules).toEqual([]);
  });
  it('SSO has nothing gateable: modules null or empty are fine, anything else is refused', () => {
    const empty = validateLicenseInput('sso', { customer: 'x', expiresAt: null, modules: [] }, null);
    expect(empty.ok && empty.value.modules).toBeNull();
    expect(fieldsOf(validateLicenseInput('sso', { customer: 'x', expiresAt: null, modules: ['visits'] }, null))).toEqual(['modules']);
  });
  it('limits the customer to 200 characters and the notes to 2000', () => {
    expect(fieldsOf(validateLicenseInput('gms', { customer: 'x'.repeat(201), expiresAt: null }, null))).toEqual(['customer']);
    expect(fieldsOf(validateLicenseInput('gms', { customer: 'x', expiresAt: null, notes: 'n'.repeat(2001) }, null))).toEqual(['notes']);
  });
  it('reports every problem at once', () => {
    expect(fieldsOf(validateLicenseInput('gms', { customer: '', expiresAt: '2027-02-30', graceDays: 999, maxUsers: 0 }, null)).sort()).toEqual(['customer', 'expiresAt', 'graceDays', 'maxUsers']);
  });
  it('non-object bodies are treated as empty', () => {
    expect(validateLicenseInput('gms', null, null).ok).toBe(false);
    expect(validateLicenseInput('gms', [], null).ok).toBe(false);
  });
});

describe('validateLicenseInput on an existing licence', () => {
  it('a field left out keeps its stored value', () => {
    const r = validateLicenseInput('gms', { maxUsers: 80 }, existing());
    expect(r).toEqual({ ok: true, value: { customer: 'Example Corp', expiresAt: '2027-01-01T00:00:00.000Z', graceDays: 14, warnDays: 30, maxUsers: 80, modules: ['visits'], notes: '' } });
  });
  it('an explicit null clears a limit, the expiry (perpetual) and the module list (all)', () => {
    const r = validateLicenseInput('gms', { maxUsers: null, expiresAt: null, modules: null }, existing());
    expect(r.ok && [r.value.maxUsers, r.value.expiresAt, r.value.modules]).toEqual([null, null, null]);
  });
  it('a bad value is still refused', () => {
    expect(fieldsOf(validateLicenseInput('gms', { warnDays: 400 }, existing()))).toEqual(['warnDays']);
  });
});

describe('validateExtendInput / extendedExpiry', () => {
  it('needs exactly one of days and expiresAt', () => {
    expect(validateExtendInput({}).ok).toBe(false);
    expect(validateExtendInput({ days: 30, expiresAt: '2028-01-01' }).ok).toBe(false);
    expect(validateExtendInput({ days: 30 })).toEqual({ ok: true, value: { days: 30 } });
    expect(validateExtendInput({ expiresAt: '2028-01-01' })).toEqual({ ok: true, value: { expiresAt: '2028-01-01T23:59:59.999Z' } });
  });
  it('days are whole and between 1 and 3650', () => {
    for (const bad of [0, -1, 1.5, 3651, '30']) expect(validateExtendInput({ days: bad }).ok).toBe(false);
    expect(validateExtendInput({ days: 3650 }).ok).toBe(true);
  });
  it('counts from the later of the current expiry and now', () => {
    const now = Date.UTC(2026, 5, 1);
    // still in the future: from the expiry
    expect(extendedExpiry('2026-07-01T00:00:00.000Z', 30, now)).toBe(new Date(Date.UTC(2026, 6, 1) + 30 * DAY_MS).toISOString());
    // lapsed: from today
    expect(extendedExpiry('2026-01-01T00:00:00.000Z', 30, now)).toBe(new Date(now + 30 * DAY_MS).toISOString());
  });
});
