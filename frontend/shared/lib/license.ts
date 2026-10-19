/**
 * Types and wording for the licence screens. The shapes are the backend's (api/v1/licenses.router.ts, licenses/status.ts); the states are the
 * contract's (docs/operations/PLATFORM-LICENSING.md section 3).
 */
export type LicenseState = 'unconfigured' | 'unknown' | 'active' | 'expiring' | 'grace' | 'expired';

export interface LicenseStatus {
  system: 'sso' | 'gms' | 'dms';
  state: LicenseState;
  customer: string | null;
  expiresAt: string | null;
  graceEndsAt: string | null;
  daysRemaining: number | null;
  warnDays: number | null;
  graceDays: number | null;
  readOnly: boolean;
  maxUsers: number | null;
  seatsUsed: number;
  modules: string[] | null;
  source: 'sso' | 'cache' | 'none';
  fetchedAt: string | null;
  version: number | null;
  enforcement: 'enforce' | 'warn' | 'off';
}

export const STATE_LABEL: Record<LicenseState, string> = {
  unconfigured: 'No licence',
  unknown: 'Unknown',
  active: 'Active',
  expiring: 'Expiring soon',
  grace: 'Grace period',
  expired: 'Expired: read-only',
};

export const STATE_BADGE: Record<LicenseState, string> = {
  unconfigured: 'ui-badge-neutral',
  unknown: 'ui-badge-neutral',
  active: 'ui-badge-success',
  expiring: 'ui-badge-warning',
  grace: 'ui-badge-warning',
  expired: 'ui-badge-danger',
};

export const formatDate = (iso: string | null): string => (iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' }) : 'never');

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${Math.abs(n) === 1 ? one : many}`;
}
