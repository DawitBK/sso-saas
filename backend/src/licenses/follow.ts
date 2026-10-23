/**
 * Clients follow SSO's own expiry (owner decision 2026-10-21): GMS and DMS stop when SSO's licence stops, whether or not they have a date of their own.
 *
 * The token SSO serves a client is built from the client's licence row, except that when SSO's own licence has an expiry that is earlier than the
 * client's (or the client never expires) the token carries SSO's expiry and warning days, and SSO's grace days capped so the hard stop is never later than
 * the client's own. So the client counts down, warns, enters its grace period and goes read-only with SSO, and recovers when SSO's licence is extended
 * (the next token carries the client's own, later, date). A licence that may also run standalone (modes include 'standalone') is not tied to SSO: it is
 * served unchanged.
 *
 * The version a client holds must only ever go up (a consumer ignores a lower one), so the served version is never lower than SSO's highest ever:
 * every change to SSO's licence, including removing it, makes the next token newer than the last. A licence installed by hand at a client
 * (offline signing, section 9) is not touched by this: it is only as strict as its own dates.
 */
import type { LicenseRecord } from './repository.js';

const DAY_MS = 86_400_000;

export function followSso(record: LicenseRecord, sso: LicenseRecord | null, ssoHighestVersion: number): LicenseRecord {
  if (record.system === 'sso') return record;
  const version = Math.max(record.version, ssoHighestVersion);
  const ssoEnds = sso?.expiresAt ? Date.parse(sso.expiresAt) : null;
  const ownEnds = record.expiresAt ? Date.parse(record.expiresAt) : null;
  const followsSso = sso !== null && ssoEnds !== null && !record.modes.includes('standalone') && (ownEnds === null || ssoEnds < ownEnds);
  if (!followsSso) return version === record.version ? record : { ...record, version };
  const room = ownEnds === null ? Number.POSITIVE_INFINITY : Math.floor((ownEnds + record.graceDays * DAY_MS - ssoEnds) / DAY_MS);
  return {
    ...record,
    expiresAt: sso.expiresAt,
    graceDays: Math.min(sso.graceDays, room),
    warnDays: sso.warnDays,
    version,
    updatedAt: Date.parse(sso.updatedAt) > Date.parse(record.updatedAt) ? sso.updatedAt : record.updatedAt,
  };
}
