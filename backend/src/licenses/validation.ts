/**
 * Validation for a licence save and an extend (docs/operations/PLATFORM-LICENSING.md section 5): dates are real, grace and warn days are
 * 0..365, max users is at least 1, module keys are in the catalogue. Pure: no database, no clock except the one passed in.
 *
 * A save on an EXISTING licence merges: a field left out keeps its stored value. A save that CREATES one must say explicitly what it expires
 * (`expiresAt`: a date, or null for "never"), so an omitted field can never silently make a licence perpetual.
 */
import { DAY_MS } from './state.js';
import { DEFAULT_LICENSE_MODES, LICENSE_MODES, moduleKeys, type LicenseSystem } from './catalog.js';
import type { LicenseRecord } from './repository.js';

export interface FieldProblem { field: string; message: string }

export type Validated<T> = { ok: true; value: T } | { ok: false; details: FieldProblem[] };

export interface LicenseFields {
  customer: string;
  expiresAt: string | null;
  graceDays: number;
  warnDays: number;
  maxUsers: number | null;
  modules: string[] | null;
  modes: string[];
  notes: string;
}

export const DEFAULT_GRACE_DAYS = 14;
export const DEFAULT_WARN_DAYS = 30;
export const MAX_DAYS = 365;
export const MAX_USERS_LIMIT = 10_000_000;
export const MAX_EXTEND_DAYS = 3650;

const MIN_YEAR = 2000;
const MAX_YEAR = 2100;
const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/;
const DATE_TIME = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,3})?)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * A real calendar date. `YYYY-MM-DD` means the END of that day (23:59:59.999 UTC), so "expires 2027-01-01" lets people work through the 1st;
 * a full ISO date-time with a zone is taken exactly as written. Anything else (no zone, 2027-02-30, a year outside 2000..2100) is refused.
 */
export function parseExpiry(input: unknown): { ok: true; iso: string } | { ok: false; message: string } {
  if (typeof input !== 'string' || input.trim() === '') return { ok: false, message: 'Enter a date (YYYY-MM-DD).' };
  const s = input.trim();
  let ms: number;
  const d = DATE_ONLY.exec(s);
  if (d) {
    const [y, m, day] = [Number(d[1]), Number(d[2]), Number(d[3])];
    const probe = new Date(Date.UTC(y, m - 1, day));
    if (probe.getUTCFullYear() !== y || probe.getUTCMonth() !== m - 1 || probe.getUTCDate() !== day) return { ok: false, message: 'That is not a real calendar date.' };
    ms = Date.UTC(y, m - 1, day, 23, 59, 59, 999);
  } else if (DATE_TIME.test(s)) {
    ms = new Date(s).getTime();
    const dayPart = DATE_TIME.exec(s)!;
    const probe = new Date(Date.UTC(Number(dayPart[1]), Number(dayPart[2]) - 1, Number(dayPart[3])));
    if (probe.getUTCDate() !== Number(dayPart[3]) || probe.getUTCMonth() !== Number(dayPart[2]) - 1) return { ok: false, message: 'That is not a real calendar date.' };
  } else {
    return { ok: false, message: 'Use YYYY-MM-DD, or a full date and time with a zone (2027-01-01T00:00:00Z).' };
  }
  if (!Number.isFinite(ms)) return { ok: false, message: 'That is not a real date.' };
  const year = new Date(ms).getUTCFullYear();
  if (year < MIN_YEAR || year > MAX_YEAR) return { ok: false, message: `The year must be between ${MIN_YEAR} and ${MAX_YEAR}.` };
  return { ok: true, iso: new Date(ms).toISOString() };
}

function intField(value: unknown, field: string, min: number, max: number, problems: FieldProblem[]): number | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < min || value > max) {
    problems.push({ field, message: `Must be a whole number from ${min} to ${max}.` });
    return undefined;
  }
  return value;
}

/** Whether `body` carries the key at all (an explicit `null` counts: it means "no limit" / "never" / "all modules"). */
const has = (body: Record<string, unknown>, key: string): boolean => Object.prototype.hasOwnProperty.call(body, key) && body[key] !== undefined;

export function validateLicenseInput(system: LicenseSystem, raw: unknown, existing: LicenseRecord | null): Validated<LicenseFields> {
  const body = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
  const problems: FieldProblem[] = [];

  // customer
  let customer = existing?.customer ?? '';
  if (has(body, 'customer')) {
    if (typeof body.customer !== 'string' || body.customer.trim() === '') problems.push({ field: 'customer', message: 'Enter the customer’s name.' });
    else if (body.customer.trim().length > 200) problems.push({ field: 'customer', message: 'At most 200 characters.' });
    else customer = body.customer.trim();
  } else if (!existing) problems.push({ field: 'customer', message: 'Enter the customer’s name.' });

  // expiresAt: explicit on create
  let expiresAt: string | null = existing?.expiresAt ?? null;
  if (has(body, 'expiresAt')) {
    if (body.expiresAt === null) expiresAt = null;
    else {
      const parsed = parseExpiry(body.expiresAt);
      if (parsed.ok) expiresAt = parsed.iso;
      else problems.push({ field: 'expiresAt', message: parsed.message });
    }
  } else if (!existing) problems.push({ field: 'expiresAt', message: 'Choose an expiry date, or say it never expires (null).' });

  let graceDays = existing?.graceDays ?? DEFAULT_GRACE_DAYS;
  if (has(body, 'graceDays')) graceDays = intField(body.graceDays, 'graceDays', 0, MAX_DAYS, problems) ?? graceDays;
  let warnDays = existing?.warnDays ?? DEFAULT_WARN_DAYS;
  if (has(body, 'warnDays')) warnDays = intField(body.warnDays, 'warnDays', 0, MAX_DAYS, problems) ?? warnDays;

  let maxUsers: number | null = existing?.maxUsers ?? null;
  if (has(body, 'maxUsers')) {
    if (body.maxUsers === null) maxUsers = null;
    else maxUsers = intField(body.maxUsers, 'maxUsers', 1, MAX_USERS_LIMIT, problems) ?? maxUsers;
  }

  let modules: string[] | null = existing?.modules ?? null;
  if (has(body, 'modules')) {
    if (body.modules === null) modules = null;
    else if (!Array.isArray(body.modules) || body.modules.some((m) => typeof m !== 'string')) {
      problems.push({ field: 'modules', message: 'A list of module keys, or null for every module.' });
    } else {
      const allowed = new Set(moduleKeys(system));
      const unknown = [...new Set(body.modules as string[])].filter((m) => !allowed.has(m));
      if (unknown.length) {
        problems.push({
          field: 'modules',
          message: allowed.size === 0 ? `${system.toUpperCase()} has no modules that can be switched off.` : `Unknown module: ${unknown.join(', ')}.`,
        });
      } else {
        // Catalogue order, no duplicates. SSO has nothing gateable, so an empty list is the same as "all" (null).
        modules = system === 'sso' ? null : moduleKeys(system).filter((k) => (body.modules as string[]).includes(k));
      }
    }
  }
  if (system === 'sso') modules = null;

  // modes: which deployment shapes this licence authorises. Never empty: a licence that authorises nothing is not a licence. SSO itself always runs as the identity provider.
  let modes: string[] = existing?.modes ?? [...DEFAULT_LICENSE_MODES];
  if (has(body, 'modes')) {
    if (!Array.isArray(body.modes) || body.modes.length === 0 || body.modes.some((m) => typeof m !== 'string' || !(LICENSE_MODES as readonly string[]).includes(m))) {
      problems.push({ field: 'modes', message: 'A non-empty list of "sso" and/or "standalone".' });
    } else {
      modes = LICENSE_MODES.filter((m) => (body.modes as string[]).includes(m));
    }
  }
  if (system === 'sso') modes = [...DEFAULT_LICENSE_MODES];

  let notes = existing?.notes ?? '';
  if (has(body, 'notes')) {
    if (typeof body.notes !== 'string' || body.notes.length > 2000) problems.push({ field: 'notes', message: 'Text of at most 2000 characters.' });
    else notes = body.notes;
  }

  if (problems.length) return { ok: false, details: problems };
  return { ok: true, value: { customer, expiresAt, graceDays, warnDays, maxUsers, modules, modes, notes } };
}

export type ExtendInput = { days: number } | { expiresAt: string };

/** `{ days }` (1..3650) or `{ expiresAt }` (a date), not both. */
export function validateExtendInput(raw: unknown): Validated<ExtendInput> {
  const body = (raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}) as Record<string, unknown>;
  const hasDays = has(body, 'days');
  const hasDate = has(body, 'expiresAt');
  if (hasDays === hasDate) return { ok: false, details: [{ field: 'days', message: 'Send either days or expiresAt, not both and not neither.' }] };
  if (hasDays) {
    const problems: FieldProblem[] = [];
    const days = intField(body.days, 'days', 1, MAX_EXTEND_DAYS, problems);
    return problems.length || days === undefined ? { ok: false, details: problems } : { ok: true, value: { days } };
  }
  const parsed = parseExpiry(body.expiresAt);
  return parsed.ok ? { ok: true, value: { expiresAt: parsed.iso } } : { ok: false, details: [{ field: 'expiresAt', message: parsed.message }] };
}

/** The new expiry for `days`: counted from the later of the current expiry and now, so extending a lapsed licence by 30 days gives 30 days from today. */
export function extendedExpiry(currentExpiresAt: string, days: number, nowMs: number): string {
  const base = Math.max(new Date(currentExpiresAt).getTime(), nowMs);
  return new Date(base + days * DAY_MS).toISOString();
}
