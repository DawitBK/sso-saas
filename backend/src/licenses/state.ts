/**
 * The licence state function (docs/operations/PLATFORM-LICENSING.md section 3).
 *
 * PURE and DEPENDENCY-FREE on purpose: GMS and DMS copy this file verbatim (they cannot import from SSO), so it imports nothing, reads no
 * clock, no environment and no database. Change it here, then change every copy. The contract's table is the specification:
 *
 *   unconfigured  no record                                              nothing
 *   unknown       (consumer only) never obtained a verified token        nothing
 *   active        perpetual, or now < expires - warnDays                  nothing
 *   expiring      expires - warnDays <= now < expires                     banner
 *   grace         expires <= now < expires + graceDays                    banner, full function
 *   expired       now >= expires + graceDays                              read-only
 *
 * Boundaries are inclusive on the lower edge: at the exact instant of `expires`, the licence is in grace (or expired when graceDays is 0);
 * at `expires + graceDays` it is expired; at `expires - warnDays` it is expiring. warnDays 0 means there is no warning window (active
 * straight to grace); graceDays 0 means no grace (expiring straight to expired).
 *
 * `daysRemaining` is the whole number of days from `now` to `expires`, truncated toward zero (2.9 days left -> 2, 0.4 days left -> 0,
 * 0.4 days past -> 0, 2.9 days past -> -2); null for a perpetual licence. `graceEndsAt` is `expires + graceDays` (null when perpetual).
 */

export type LicenseState = 'unconfigured' | 'unknown' | 'active' | 'expiring' | 'grace' | 'expired';

export interface LicenseDates {
  /** Epoch milliseconds, an ISO string or a Date. null = perpetual. */
  expiresAt: number | string | Date | null;
  graceDays: number;
  warnDays: number;
}

export interface LicenseComputed {
  state: LicenseState;
  daysRemaining: number | null;
  /** ISO string, or null when perpetual. */
  expiresAt: string | null;
  /** ISO string (expires + graceDays), or null when perpetual. */
  graceEndsAt: string | null;
  /** True only in the `expired` state. Whether it is ENFORCED is the caller's business (LICENSE_ENFORCEMENT). */
  readOnly: boolean;
}

export const DAY_MS = 86_400_000;

function toMs(value: number | string | Date): number {
  return value instanceof Date ? value.getTime() : typeof value === 'number' ? value : new Date(value).getTime();
}

/** `license` null means no record. `now` is epoch milliseconds or a Date (the server clock is the only time source). */
export function computeLicenseState(license: LicenseDates | null, now: number | Date): LicenseComputed {
  if (!license) return { state: 'unconfigured', daysRemaining: null, expiresAt: null, graceEndsAt: null, readOnly: false };
  const nowMs = toMs(now);
  if (license.expiresAt === null || license.expiresAt === undefined) {
    return { state: 'active', daysRemaining: null, expiresAt: null, graceEndsAt: null, readOnly: false };
  }
  const expiresMs = toMs(license.expiresAt);
  // An unreadable date must never lock anyone: treat it like a record that cannot be understood, i.e. no enforcement.
  if (!Number.isFinite(expiresMs) || !Number.isFinite(nowMs)) {
    return { state: 'unknown', daysRemaining: null, expiresAt: null, graceEndsAt: null, readOnly: false };
  }
  const graceEndsMs = expiresMs + license.graceDays * DAY_MS;
  const warnStartMs = expiresMs - license.warnDays * DAY_MS;
  const remaining = Math.trunc((expiresMs - nowMs) / DAY_MS);

  let state: LicenseState;
  if (nowMs >= graceEndsMs) state = 'expired';
  else if (nowMs >= expiresMs) state = 'grace';
  else if (nowMs >= warnStartMs) state = 'expiring';
  else state = 'active';

  return {
    state,
    daysRemaining: remaining === 0 ? 0 : remaining, // never -0
    expiresAt: new Date(expiresMs).toISOString(),
    graceEndsAt: new Date(graceEndsMs).toISOString(),
    readOnly: state === 'expired',
  };
}
