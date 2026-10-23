/**
 * The licence version rule (src/licenses/version.ts, docs/operations/PLATFORM-LICENSING.md section 4.1): the version is the issue time in seconds since
 * 2026-01-01 UTC, so the licence issued last wins in every system. No database. The offline signer is run for real from source with tsx.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { decodeJwt } from 'jose';
import {
  LEGACY_VERSION_BELOW, LICENSE_VERSION_EPOCH_MS, MAX_LICENSE_VERSION,
  isValidLicenseVersion, issueTimeOfVersion, nextLicenseVersion, versionFromTime,
} from '../src/licenses/version.js';

const T = Date.UTC(2026, 9, 21, 9, 0, 0); // 2026-10-21 09:00:00 UTC

describe('versionFromTime', () => {
  it('is the whole seconds since 2026-01-01 00:00:00 UTC', () => {
    expect(LICENSE_VERSION_EPOCH_MS).toBe(Date.UTC(2026, 0, 1));
    expect(versionFromTime(LICENSE_VERSION_EPOCH_MS + 5_000)).toBe(5);
    expect(versionFromTime(LICENSE_VERSION_EPOCH_MS + 5_999)).toBe(5);
    expect(versionFromTime(T)).toBe((T - LICENSE_VERSION_EPOCH_MS) / 1000);
  });

  it('is at least 1, even at or before the epoch', () => {
    expect(versionFromTime(LICENSE_VERSION_EPOCH_MS)).toBe(1);
    expect(versionFromTime(LICENSE_VERSION_EPOCH_MS - 1_000_000)).toBe(1);
    expect(versionFromTime(0)).toBe(1);
  });

  it('a later time gives a higher version (equal within one second)', () => {
    expect(versionFromTime(T + 1_000)).toBe(versionFromTime(T) + 1);
    expect(versionFromTime(T + 100)).toBeGreaterThanOrEqual(versionFromTime(T));
  });

  it('fits a 32-bit signed integer until 2094, and refuses a time beyond it (no silent overflow)', () => {
    expect(versionFromTime(Date.UTC(2093, 11, 31))).toBeLessThan(MAX_LICENSE_VERSION);
    expect(() => versionFromTime(Date.UTC(2095, 0, 1))).toThrow(RangeError);
    expect(() => versionFromTime(Number.NaN)).toThrow(RangeError);
  });

  it('plain Unix seconds would overflow 32 bits in 2038; this rule does not (why it is not used)', () => {
    expect(Math.floor(T / 1000)).toBeLessThan(MAX_LICENSE_VERSION);
    expect(Math.floor(Date.UTC(2039, 0, 1) / 1000)).toBeGreaterThan(MAX_LICENSE_VERSION);
    expect(versionFromTime(Date.UTC(2039, 0, 1))).toBeLessThan(MAX_LICENSE_VERSION);
  });
});

describe('nextLicenseVersion(highestSoFar, now)', () => {
  it('a system with no licence yet gets the time version', () => {
    expect(nextLicenseVersion(0, T)).toBe(versionFromTime(T));
  });

  it('old hand-numbered versions (1..6) are superseded by the first time-based one', () => {
    for (const old of [1, 2, 3, 4, 5, 6]) expect(nextLicenseVersion(old, T)).toBe(versionFromTime(T));
    expect(nextLicenseVersion(6, T)).toBeGreaterThan(LEGACY_VERSION_BELOW);
  });

  it('a later issue is higher than an earlier one', () => {
    const first = nextLicenseVersion(0, T);
    expect(nextLicenseVersion(first, T + 60_000)).toBe(versionFromTime(T + 60_000));
    expect(nextLicenseVersion(first, T + 60_000)).toBeGreaterThan(first);
  });

  it('the same second: strictly higher, by one each time', () => {
    const first = nextLicenseVersion(0, T);
    const second = nextLicenseVersion(first, T + 400);
    const third = nextLicenseVersion(second, T + 800);
    expect([second, third]).toEqual([first + 1, first + 2]);
  });

  it('the clock stepping back never lowers it (two hours back)', () => {
    const first = nextLicenseVersion(0, T);
    expect(nextLicenseVersion(first, T - 7_200_000)).toBe(first + 1);
  });

  it('revoke then create: the revoke takes a number, the new licence is above it', () => {
    const created = nextLicenseVersion(0, T);
    const revoke = nextLicenseVersion(created, T + 5_000);
    const recreated = nextLicenseVersion(revoke, T + 5_000); // same second as the revoke
    expect(revoke).toBeGreaterThan(created);
    expect(recreated).toBe(revoke + 1);
  });

  it('refuses to run past the largest 32-bit version', () => {
    expect(() => nextLicenseVersion(MAX_LICENSE_VERSION, T)).toThrow(RangeError);
  });
});

describe('issueTimeOfVersion and isValidLicenseVersion', () => {
  it('turns a time-based version back into its issue time, and gives no time for an old hand-numbered one', () => {
    expect(issueTimeOfVersion(versionFromTime(T))).toBe(T);
    expect(issueTimeOfVersion(7)).toBeNull();
    expect(issueTimeOfVersion(LEGACY_VERSION_BELOW - 1)).toBeNull();
  });

  it('accepts only whole numbers from 1 to 2147483647', () => {
    for (const ok of [1, 4, 25_000_000, MAX_LICENSE_VERSION]) expect(isValidLicenseVersion(ok)).toBe(true);
    for (const bad of [0, -1, 1.5, Number.NaN, MAX_LICENSE_VERSION + 1, '5', null, undefined]) expect(isValidLicenseVersion(bad)).toBe(false);
  });
});

describe('npm run license:sign (the offline signer, run from source)', () => {
  let dir = '';
  let keyFile = '';
  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'license-version-sign-'));
    keyFile = path.join(dir, 'offline.pem');
    fs.writeFileSync(keyFile, crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  const sign = (...extra: string[]) =>
    spawnSync(
      process.execPath,
      ['node_modules/tsx/dist/cli.mjs', 'scripts/license-sign.ts', '--key', keyFile, '--system', 'dms', '--customer', 'Example Corp', '--expires', '2030-01-01', ...extra],
      { cwd: process.cwd(), encoding: 'utf8', timeout: 60_000 },
    );

  it('without --version the version is the issue time; stdout is the token only; stderr says what it replaces', () => {
    const lo = versionFromTime(Date.now());
    const run = sign();
    const hi = versionFromTime(Date.now());
    expect(run.status).toBe(0);
    const token = run.stdout.trim();
    expect(token.split('.')).toHaveLength(3);
    expect(token).not.toMatch(/\s/);
    const ver = (decodeJwt(token) as { ver: number }).ver;
    expect(ver).toBeGreaterThanOrEqual(lo);
    expect(ver).toBeLessThanOrEqual(hi);
    expect(run.stderr).toContain(`version ${ver}`);
    expect(run.stderr).toMatch(/This replaces every dms licence issued before \d{4}-\d{2}-\d{2}T/);
  }, 90_000);

  it('an explicit --version is used as given (the recovery tool), and says which time it names', () => {
    const v = versionFromTime(Date.now()) + 86_400; // a day ahead
    const run = sign('--version', String(v));
    expect(run.status).toBe(0);
    expect((decodeJwt(run.stdout.trim()) as { ver: number }).ver).toBe(v);
    expect(run.stderr).toContain(new Date(issueTimeOfVersion(v) as number).toISOString());
    expect(run.stderr).toContain('This replaces every dms licence issued before');
  }, 90_000);

  it('an explicit old-style number is accepted but the tool warns that it will be ignored', () => {
    const run = sign('--version', '4');
    expect(run.status).toBe(0);
    expect((decodeJwt(run.stdout.trim()) as { ver: number }).ver).toBe(4);
    expect(run.stderr).toMatch(/IGNORE/);
  }, 90_000);

  it('a --version that is not a positive whole number (or does not fit 32 bits) is refused and prints no token', () => {
    for (const bad of ['0', '-3', '1.5', 'abc', '2147483648']) {
      const run = sign('--version', bad);
      expect(run.status).toBe(2);
      expect(run.stdout.trim()).toBe('');
      expect(run.stderr).toContain('--version must be a whole number');
    }
    const missing = sign('--version');
    expect(missing.status).toBe(2);
    expect(missing.stdout.trim()).toBe('');
  }, 120_000);
});
