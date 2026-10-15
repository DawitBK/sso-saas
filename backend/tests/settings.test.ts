/**
 * Platform settings: the registry (settings/registry.ts) and the run-time store (settings/store.ts).
 */
const mockQuery = jest.fn();
jest.mock('../src/db/pool.js', () => ({ pool: { query: (...a: unknown[]) => mockQuery(...a) } }));
jest.mock('../src/logging/logger.js', () => ({ logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() } }));
jest.mock('../src/config.js', () => ({
  IDP_CONFIG: { loginLockoutEnabled: false, adminRequireMfa: false, ttl: { accessToken: 3600, idToken: 3600, refreshToken: 86400, session: 14 * 86400 } },
}));

import { contrastRatio, parseSettingValue, readableInk, settingDef, SETTINGS, SETTING_GROUPS } from '../src/settings/registry.js';
import {
  __setSnapshotForTests, getBool, getNumber, getString, listSettingStates, loadSettings, resetSetting, setAppIdsProvider, setSetting,
} from '../src/settings/store.js';

const def = (key: string) => {
  const d = settingDef(key);
  if (!d) throw new Error(`no such setting ${key}`);
  return d;
};

beforeEach(() => {
  mockQuery.mockReset();
  mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
  __setSnapshotForTests({});
  setAppIdsProvider(() => ['edams', 'gms']);
});

describe('the registry itself', () => {
  it('has unique keys, and every group a setting names exists', () => {
    const keys = SETTINGS.map((s) => s.key);
    expect(new Set(keys).size).toBe(keys.length);
    const groups = new Set(SETTING_GROUPS.map((g) => g.id));
    for (const s of SETTINGS) expect(groups.has(s.group)).toBe(true);
  });

  it('every default passes its own validation (a fresh install must never start with an invalid value)', () => {
    for (const s of SETTINGS) {
      const r = parseSettingValue(s, s.defaultValue(), ['edams', 'gms']);
      expect({ key: s.key, ok: r.ok }).toEqual({ key: s.key, ok: true });
    }
  });

  it('everything that can lock people out or weaken sign-in is platform-administrator-only', () => {
    for (const key of ['password.minLength', 'password.blockCommon', 'lockout.enabled', 'lockout.threshold', 'lockout.minutes', 'mfa.requireForAdmins', 'ttl.accessTokenSeconds', 'ttl.idTokenSeconds', 'ttl.refreshTokenHours', 'ttl.ssoSessionHours', 'ttl.portalSessionHours', 'retention.loginEventDays']) {
      expect({ key, by: def(key).editableBy }).toEqual({ key, by: 'platform' });
    }
    for (const key of ['branding.productName', 'branding.loginNotice', 'portal.hiddenApps']) expect(def(key).editableBy).toBe('admin');
  });
});

describe('parseSettingValue', () => {
  it('int: whole numbers inside the limits only', () => {
    const d = def('password.minLength');
    expect(parseSettingValue(d, 12)).toEqual({ ok: true, value: 12 });
    for (const bad of [7, 65, 12.5, '12', null, NaN]) expect(parseSettingValue(d, bad).ok).toBe(false);
  });

  it('bool: real booleans only', () => {
    const d = def('lockout.enabled');
    expect(parseSettingValue(d, true)).toEqual({ ok: true, value: true });
    expect(parseSettingValue(d, 'true').ok).toBe(false);
    expect(parseSettingValue(d, 1).ok).toBe(false);
  });

  it('text: trimmed, length-limited, no control characters, no newline unless multiline', () => {
    expect(parseSettingValue(def('branding.productName'), '  Acme  ')).toEqual({ ok: true, value: 'Acme' });
    expect(parseSettingValue(def('branding.productName'), 'x'.repeat(61)).ok).toBe(false);
    expect(parseSettingValue(def('branding.productName'), 'a\u0000b').ok).toBe(false);
    expect(parseSettingValue(def('branding.productName'), 'a\nb').ok).toBe(false);
    expect(parseSettingValue(def('branding.loginNotice'), 'line one\r\nline two')).toEqual({ ok: true, value: 'line one\nline two' });
    expect(parseSettingValue(def('branding.productName'), 5).ok).toBe(false);
  });

  it('text may be empty (to clear a notice)', () => {
    expect(parseSettingValue(def('branding.loginNotice'), '   ')).toEqual({ ok: true, value: '' });
  });

  it('color: #rrggbb only, normalised to lower case', () => {
    const d = def('branding.accentColor');
    expect(parseSettingValue(d, '#1D4ED8')).toEqual({ ok: true, value: '#1d4ed8' });
    for (const bad of ['1d4ed8', '#fff', '#12345g', 'red', 'url(x)', '#1d4ed8;color:red', 5]) expect(parseSettingValue(d, bad).ok).toBe(false);
  });

  it('color: refuses an accent too pale for the page it sits on', () => {
    const light = parseSettingValue(def('branding.accentColor'), '#ffff99');
    expect(light.ok).toBe(false);
    if (!light.ok) expect(light.error).toMatch(/contrast/);
    expect(parseSettingValue(def('branding.accentColorDark'), '#101830').ok).toBe(false);
    expect(parseSettingValue(def('branding.accentColorDark'), '#64ffda').ok).toBe(true);
  });

  it('apps: only known launcher ids, de-duplicated and sorted', () => {
    const d = def('portal.hiddenApps');
    expect(parseSettingValue(d, ['gms', 'edams', 'gms'], ['edams', 'gms'])).toEqual({ ok: true, value: ['edams', 'gms'] });
    expect(parseSettingValue(d, ['nope'], ['edams', 'gms']).ok).toBe(false);
    expect(parseSettingValue(d, 'edams', ['edams']).ok).toBe(false);
  });
});

describe('colour maths', () => {
  it('black on white is 21:1 and a colour against itself is 1:1', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 0);
    expect(contrastRatio('#336699', '#336699')).toBeCloseTo(1, 5);
  });
  it('picks readable ink for a button', () => {
    expect(readableInk('#166534')).toBe('#ffffff');
    expect(readableInk('#64ffda')).toBe('#000000');
  });
});

describe('the store', () => {
  it('serves the default until something is stored', () => {
    expect(getNumber('password.minLength')).toBe(8);
    expect(getBool('lockout.enabled')).toBe(false);
    expect(getNumber('ttl.refreshTokenHours')).toBe(24);
    expect(getNumber('ttl.ssoSessionHours')).toBe(336);
  });

  it('setSetting validates, writes and applies at once', async () => {
    const r = await setSetting('password.minLength', 14, 'admin@x.co');
    expect(r).toMatchObject({ ok: true, change: { key: 'password.minLength', before: 8, after: 14 } });
    expect(getNumber('password.minLength')).toBe(14);
    expect(mockQuery).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO idp_settings'), ['password.minLength', '14', 'admin@x.co']);
  });

  it('refuses an invalid value and stores nothing', async () => {
    const r = await setSetting('password.minLength', 3, 'a@x.co');
    expect(r.ok).toBe(false);
    expect(mockQuery).not.toHaveBeenCalled();
    expect(getNumber('password.minLength')).toBe(8);
  });

  it('refuses an unknown key', async () => {
    expect((await setSetting('nope.nothing', 1, 'a@x.co')).ok).toBe(false);
  });

  it('resetSetting removes the override', async () => {
    await setSetting('branding.productName', 'Acme', 'a@x.co');
    expect(getString('branding.productName')).toBe('Acme');
    const r = await resetSetting('branding.productName');
    expect(r).toMatchObject({ ok: true, change: { before: 'Acme', after: 'Example Corp Identity' } });
    expect(getString('branding.productName')).toBe('Example Corp Identity');
  });

  it('loadSettings reads stored rows, ignores unknown keys and invalid values', async () => {
    mockQuery.mockResolvedValueOnce({
      rows: [
        { key: 'password.minLength', value: 12, updated_at: new Date(), updated_by: 'a@x.co' },
        { key: 'password.blockCommon', value: 'yes please', updated_at: new Date(), updated_by: 'a@x.co' },
        { key: 'retired.setting', value: 1, updated_at: new Date(), updated_by: 'a@x.co' },
      ],
    });
    await loadSettings();
    expect(getNumber('password.minLength')).toBe(12);
    expect(getBool('password.blockCommon')).toBe(true);
  });

  it('keeps the last known values when the database cannot be read', async () => {
    await setSetting('password.minLength', 20, 'a@x.co');
    mockQuery.mockRejectedValueOnce(new Error('connection lost'));
    await loadSettings();
    expect(getNumber('password.minLength')).toBe(20);
  });

  it('survives the table not existing yet (migration not applied)', async () => {
    mockQuery.mockRejectedValueOnce(Object.assign(new Error('relation "idp_settings" does not exist'), { code: '42P01' }));
    await expect(loadSettings()).resolves.toBeUndefined();
    expect(getNumber('password.minLength')).toBe(8);
  });

  it('listSettingStates reports where each value comes from', async () => {
    await setSetting('password.minLength', 10, 'platform');
    const states = listSettingStates();
    const minLength = states.find((s) => s.def.key === 'password.minLength');
    expect(minLength).toMatchObject({ value: 10, defaultValue: 8, source: 'stored', updatedBy: 'platform' });
    expect(states.find((s) => s.def.key === 'password.blockCommon')?.source).toBe('default');
  });
});
