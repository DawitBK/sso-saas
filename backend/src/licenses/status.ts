/**
 * The status shape every system answers at GET /api/v1/license/status (docs/operations/PLATFORM-LICENSING.md section 5), and SSO's own
 * licence read from its database: cached for a few seconds, failing OPEN (a database hiccup must never turn into a read-only SSO).
 */
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';
import { computeLicenseState, type LicenseState } from './state.js';
import { computeEntitlement, type DeploymentMode, type LicenseReason } from './entitlement.js';
import { countSeatsUsed, findLicense, type LicenseRecord } from './repository.js';
import type { LicenseSystem } from './catalog.js';

export interface LicenseStatus {
  system: LicenseSystem;
  state: LicenseState;
  customer: string | null;
  expiresAt: string | null;
  graceEndsAt: string | null;
  daysRemaining: number | null;
  warnDays: number | null;
  graceDays: number | null;
  /** True when the licence is in the `expired` state AND this process enforces it (LICENSE_ENFORCEMENT=enforce). */
  readOnly: boolean;
  maxUsers: number | null;
  seatsUsed: number;
  modules: string[] | null;
  source: 'sso' | 'cache' | 'none';
  fetchedAt: string | null;
  version: number | null;
  /** SSO's own enforcement mode, so the console can say "warning only" when it is not blocking. */
  enforcement: 'enforce' | 'warn' | 'off';
  /** Section 9: LICENSE_REQUIRED, whether the system is entitled to be used, why not, and the deployment shape it computed. */
  required: boolean;
  licensed: boolean;
  reason: LicenseReason | null;
  deployment: DeploymentMode;
}

/** The status of `record` at `nowMs`. `seatsUsed` is passed in (a database read the pure part must not do). */
export function buildStatus(system: LicenseSystem, record: LicenseRecord | null, seatsUsed: number, nowMs: number): LicenseStatus {
  const enforcement = IDP_CONFIG.licenseEnforcement;
  // `off` switches the whole feature off: no state, no banner, nothing enforced.
  const computed = enforcement === 'off' ? computeLicenseState(null, nowMs) : computeLicenseState(record, nowMs);
  const live = enforcement === 'off' ? null : record;
  // SSO is always the identity provider itself, so its deployment shape is 'sso'. `off` switches the whole feature off, entitlement included.
  const entitlement =
    enforcement === 'off'
      ? { licensed: true, reason: null }
      : computeEntitlement({ required: IDP_CONFIG.licenseRequired, state: computed.state, modes: live?.modes, deployment: 'sso' });
  return {
    system,
    state: computed.state,
    customer: live?.customer ?? null,
    expiresAt: computed.expiresAt,
    graceEndsAt: computed.graceEndsAt,
    daysRemaining: computed.daysRemaining,
    warnDays: live?.warnDays ?? null,
    graceDays: live?.graceDays ?? null,
    readOnly: computed.readOnly && enforcement === 'enforce',
    maxUsers: live?.maxUsers ?? null,
    seatsUsed,
    modules: live?.modules ?? null,
    source: live ? 'sso' : 'none',
    fetchedAt: new Date(nowMs).toISOString(),
    version: live?.version ?? null,
    enforcement,
    required: IDP_CONFIG.licenseRequired,
    licensed: entitlement.licensed,
    reason: entitlement.reason,
    deployment: 'sso',
  };
}

// ── SSO's own licence, cached ──────────────────────────────────────────────────────────────────────────────────────────────────
const OWN_TTL_MS = 5_000;
let own: { record: LicenseRecord | null; at: number } | null = null;
let ownRefresh: Promise<void> | null = null;

/** Forget the cached row (after this process changed it, and in tests). Another process's change is picked up within OWN_TTL_MS. */
export function invalidateOwnLicense(): void {
  own = null;
}

/** SSO's own licence row, at most 5 seconds old. A failed read keeps the last known value (null if there never was one): fail open. */
export async function ownLicenseRecord(nowMs: number = Date.now()): Promise<LicenseRecord | null> {
  if (own && nowMs - own.at < OWN_TTL_MS) return own.record;
  if (!ownRefresh) {
    ownRefresh = (async () => {
      try {
        const record = await findLicense('sso');
        own = { record, at: Date.now() };
      } catch (err) {
        logger.warn({ err }, '[idp:license] could not read SSO’s own licence; keeping the last known state');
        own = { record: own?.record ?? null, at: Date.now() };
      } finally {
        ownRefresh = null;
      }
    })();
  }
  await ownRefresh;
  return own?.record ?? null;
}

export async function ownLicenseStatus(nowMs: number = Date.now()): Promise<LicenseStatus> {
  const record = await ownLicenseRecord(nowMs);
  let seats = 0;
  try {
    seats = await countSeatsUsed();
  } catch (err) {
    logger.warn({ err }, '[idp:license] could not count seats');
  }
  return buildStatus('sso', record, seats, nowMs);
}
