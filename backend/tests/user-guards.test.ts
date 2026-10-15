import {
  AD_PASSWORD_RESET_MESSAGE,
  SELF_DISABLE_MESSAGE,
  passwordResetRefusal,
  selfDisableRefusal,
} from '../src/admin/user-guards.js';
import { sameUriSet } from '../src/oidc/clients.js';
import { disableWarning } from '../src/auth/revoke.js';
import { parseIsoDate } from '../src/api/v1/admin.router.js';

describe('selfDisableRefusal', () => {
  it('refuses only when the actor is the target', () => {
    expect(selfDisableRefusal('a', 'a')).toBe(SELF_DISABLE_MESSAGE);
    expect(selfDisableRefusal('a', 'b')).toBeNull();
    expect(selfDisableRefusal(undefined, 'b')).toBeNull();
  });
});

describe('passwordResetRefusal', () => {
  it('allows local accounts and refuses Active Directory (and anything unknown)', () => {
    expect(passwordResetRefusal('local')).toBeNull();
    expect(passwordResetRefusal('ad')).toBe(AD_PASSWORD_RESET_MESSAGE);
    expect(passwordResetRefusal(undefined)).toBe(AD_PASSWORD_RESET_MESSAGE);
  });
});

describe('sameUriSet', () => {
  it('ignores order and repeats, notices a difference', () => {
    expect(sameUriSet(['a', 'b'], ['b', 'a', 'a'])).toBe(true);
    expect(sameUriSet(['a'], ['a', 'b'])).toBe(false);
    expect(sameUriSet(null, [])).toBe(true);
    expect(sameUriSet(['http://localhost:7101/cb'], ['https://portal.example/cb'])).toBe(false);
  });
});

describe('disableWarning', () => {
  const ok = { oidcArtifacts: 0, portalSessions: 0, gatewaySessions: 0, pendingLogins: 0, gmsSessions: 0, dmsNotified: true } as const;
  it('is null when everything was reached', () => {
    expect(disableWarning(null)).toBeNull();
    expect(disableWarning({ ...ok })).toBeNull();
  });
  it('names exactly the systems that were not reached', () => {
    expect(disableWarning({ ...ok, dmsNotified: false })).toMatch(/DMS did not confirm/);
    expect(disableWarning({ ...ok, dmsNotified: false })).not.toMatch(/GMS/);
    expect(disableWarning({ ...ok, gmsSessions: 'failed' })).toMatch(/GMS could not be reached/);
    expect(disableWarning({ ...ok, gmsSessions: 'failed' })).not.toMatch(/DMS/);
  });
});

describe('parseIsoDate', () => {
  it('accepts real calendar dates only', () => {
    expect(parseIsoDate('2026-02-28')).toBe('2026-02-28');
    expect(parseIsoDate('2026-02-30')).toBeNull();
    expect(parseIsoDate('26-02-28')).toBeNull();
    expect(parseIsoDate('')).toBeNull();
    expect(parseIsoDate(undefined)).toBeNull();
    expect(parseIsoDate("2026-01-01'; DROP TABLE x;--")).toBeNull();
  });
});
