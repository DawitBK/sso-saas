/**
 * The pure parts of owner verification: the setting's default per environment, the lock schedule, recovery codes, address masking and the
 * enrolment helpers. No database.
 */
import path from 'node:path';
import { emailProblem, isInside } from '../src/owner/enrol.js';
import { maskAddress, smtpConfigured, smtpFingerprint } from '../src/owner/mailer.js';
import { LOCK_SECONDS_BY_LEVEL, TICKET_TTL_SECONDS, lockSeconds, parseOwnerAuthenticatorRequired, parseOwnerVerificationRequired } from '../src/owner/policy.js';
import { generateRecoveryCodes, matchRecoveryCode, normaliseRecoveryCode } from '../src/owner/recovery.js';
import { deriveKeys } from '../src/owner/seal.js';

describe('OWNER_VERIFICATION_REQUIRED', () => {
  it('defaults to true in production, the mirror and a non-local issuer; false in development and test', () => {
    expect(parseOwnerVerificationRequired(undefined, 'production', true)).toEqual({ required: true, explicit: false });
    expect(parseOwnerVerificationRequired('', 'mirror', false)).toEqual({ required: true, explicit: false });
    expect(parseOwnerVerificationRequired(undefined, 'development', true).required).toBe(true);
    expect(parseOwnerVerificationRequired(undefined, 'development', false)).toEqual({ required: false, explicit: false });
    expect(parseOwnerVerificationRequired(undefined, 'test', false).required).toBe(false);
  });

  it('an explicit value wins and is reported as explicit', () => {
    expect(parseOwnerVerificationRequired('false', 'production', true)).toEqual({ required: false, explicit: true });
    expect(parseOwnerVerificationRequired(' TRUE ', 'development', false)).toEqual({ required: true, explicit: true });
  });

  it('an unrecognised word falls back to the default for the environment (never silently off in production)', () => {
    expect(parseOwnerVerificationRequired('maybe', 'production', true).required).toBe(true);
  });
});

describe('OWNER_AUTHENTICATOR_REQUIRED', () => {
  it('defaults to false everywhere (owner decision 2026-10-21: no phone authenticator unless asked for)', () => {
    expect(parseOwnerAuthenticatorRequired(undefined)).toEqual({ required: false, explicit: false });
    expect(parseOwnerAuthenticatorRequired('')).toEqual({ required: false, explicit: false });
    expect(parseOwnerAuthenticatorRequired('false')).toEqual({ required: false, explicit: true });
  });

  it('only the word true turns it on (any case, any padding)', () => {
    expect(parseOwnerAuthenticatorRequired('true')).toEqual({ required: true, explicit: true });
    expect(parseOwnerAuthenticatorRequired('  TRUE ')).toEqual({ required: true, explicit: true });
  });

  it('a typo or any other word leaves it off', () => {
    for (const v of ['ture', 'yes', '1', 'on', 'enabled', 'maybe']) expect(parseOwnerAuthenticatorRequired(v).required).toBe(false);
  });
});

describe('policy numbers', () => {
  it('a ticket lives at most five minutes', () => {
    expect(TICKET_TTL_SECONDS).toBeLessThanOrEqual(300);
  });
  it('the lock escalates and the last level repeats', () => {
    expect(lockSeconds(0)).toBe(300);
    for (let i = 1; i < LOCK_SECONDS_BY_LEVEL.length; i += 1) expect(lockSeconds(i)).toBeGreaterThan(lockSeconds(i - 1));
    expect(lockSeconds(99)).toBe(lockSeconds(LOCK_SECONDS_BY_LEVEL.length - 1));
    expect(lockSeconds(-3)).toBe(300);
  });
});

describe('recovery codes', () => {
  const keys = deriveKeys(Buffer.alloc(32, 7));
  it('are twenty characters in four groups, all different, and only their keyed hashes are kept', () => {
    const { codes, records } = generateRecoveryCodes(keys, 10);
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) expect(c).toMatch(/^[A-HJ-NP-Z2-9]{5}(-[A-HJ-NP-Z2-9]{5}){3}$/);
    for (const r of records) expect(JSON.stringify(r)).not.toContain(normaliseRecoveryCode(codes[0] as string));
  });
  it('match whatever the case, spacing or dashes; a wrong or short one matches nothing; a different key matches nothing', () => {
    const { codes, records } = generateRecoveryCodes(keys, 3);
    const c = codes[1] as string;
    expect(matchRecoveryCode(keys, records, c.toLowerCase().replace(/-/g, ' '))).toBe(records[1]!.id);
    expect(matchRecoveryCode(keys, records, 'AAAAA-AAAAA-AAAAA-AAAAA')).toBeNull();
    expect(matchRecoveryCode(keys, records, c.slice(0, 10))).toBeNull();
    expect(matchRecoveryCode(deriveKeys(Buffer.alloc(32, 9)), records, c)).toBeNull();
  });
});

describe('mail helpers', () => {
  it('masks an address', () => {
    expect(maskAddress('someone@example.org')).toBe('s***@e***.org');
    expect(maskAddress('nonsense')).toBe('***');
  });
  it('the relay fingerprint changes with host, port, TLS and account but not the password or sender', () => {
    const base = { host: 'smtp.a.invalid', port: 587, secure: false, user: 'u', pass: 'p1', from: 'f@a.invalid' };
    const fp = smtpFingerprint(base);
    expect(fp).toHaveLength(32);
    expect(smtpFingerprint({ ...base, pass: 'p2', from: 'g@a.invalid' })).toBe(fp);
    expect(smtpFingerprint({ ...base, host: 'smtp.b.invalid' })).not.toBe(fp);
    expect(smtpFingerprint({ ...base, port: 465 })).not.toBe(fp);
    expect(smtpFingerprint({ ...base, secure: true })).not.toBe(fp);
    expect(smtpFingerprint({ ...base, user: 'other' })).not.toBe(fp);
    expect(smtpFingerprint({ ...base, host: '' })).toBe('');
    expect(smtpConfigured({ ...base, host: '' })).toBe(false);
    expect(smtpConfigured(base)).toBe(true);
  });
});

describe('enrolment helpers', () => {
  it('a key file inside the repository is refused, one outside is fine', () => {
    const root = path.resolve('C:/repo-root');
    expect(isInside(path.join(root, 'SSO', 'key'), root)).toBe(true);
    expect(isInside(root, root)).toBe(true);
    expect(isInside(path.resolve('C:/secrets/key'), root)).toBe(false);
    expect(isInside(path.join(root, '..', 'elsewhere', 'key'), root)).toBe(false);
  });
  it('checks the shape of an address', () => {
    expect(emailProblem('a@b.co')).toBeNull();
    expect(emailProblem('not an address')).not.toBeNull();
    expect(emailProblem(`${'x'.repeat(250)}@b.co`)).not.toBeNull();
  });
});
