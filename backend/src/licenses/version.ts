/**
 * The licence version rule (docs/operations/PLATFORM-LICENSING.md section 4): ONE rule for every way a licence is issued.
 *
 * A licence's `ver` is the number of SECONDS since 2026-01-01 00:00:00 UTC at the moment it was issued. A consumer keeps the highest `ver` it has
 * seen and ignores any lower one, so the licence issued LATEST always wins, whether it came from the SSO console, the offline signer
 * (`npm run license:sign`) or the development issuer. There is no counter to keep and no number to type.
 *
 * Plain Unix seconds are not used: they pass the 32-bit signed integer limit (the `licenses.version` and `license_events.version` columns are
 * INTEGER) in 2038, these do not until 2094. So no database migration is needed.
 *
 * Dependency-free on purpose (scripts import it without loading config or a database).
 */

/** The fixed epoch of every licence version. Never change it: that would make new versions older than old ones. */
export const LICENSE_VERSION_EPOCH_MS = Date.UTC(2026, 0, 1);

/** The largest value the INTEGER columns (and a 32-bit consumer) can hold. */
export const MAX_LICENSE_VERSION = 2_147_483_647;

/**
 * Versions below this were numbered by hand or by the old counter (1, 2, 3 ...); they are not times. Eleven days after the epoch, and the rule
 * took effect long after that, so no time-based version is ever below it.
 */
export const LEGACY_VERSION_BELOW = 1_000_000;

/** The version for a licence issued at `ms` (epoch milliseconds): whole seconds since the epoch, at least 1. */
export function versionFromTime(ms: number): number {
  if (!Number.isFinite(ms)) throw new RangeError('versionFromTime: the time must be a finite number of milliseconds.');
  const v = Math.max(1, Math.floor((ms - LICENSE_VERSION_EPOCH_MS) / 1000));
  if (v > MAX_LICENSE_VERSION) throw new RangeError('versionFromTime: the time is beyond the year 2094, the last second a licence version can name.');
  return v;
}

/**
 * The version for the next licence of a system whose highest version so far (revoked licences included) is `highestSoFar`: the time-based
 * version, but never at or below anything already issued, so it stays strictly increasing if the clock steps back, in the same second, and
 * across a revoke (a revoke takes a number too).
 */
export function nextLicenseVersion(highestSoFar: number, nowMs: number): number {
  const next = Math.max(Math.max(0, highestSoFar) + 1, versionFromTime(nowMs));
  if (next > MAX_LICENSE_VERSION) throw new RangeError('The licence version space is used up (the next version would not fit a 32-bit integer).');
  return next;
}

/** The issue time a time-based version names, as epoch milliseconds, or null for an old hand-numbered version (1, 2, 3 ...). */
export function issueTimeOfVersion(version: number): number | null {
  if (!Number.isInteger(version) || version < LEGACY_VERSION_BELOW) return null;
  return LICENSE_VERSION_EPOCH_MS + version * 1000;
}

/** True for a whole number a licence version may be (what `--version` accepts). */
export function isValidLicenseVersion(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= MAX_LICENSE_VERSION;
}
