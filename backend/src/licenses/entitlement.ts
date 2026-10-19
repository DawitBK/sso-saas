/**
 * Entitlement: whether a system may be used at all (docs/operations/PLATFORM-LICENSING.md section 9). A layer ON TOP of the state function, which it
 * never changes: `expired` stays read-only, this only adds "no licence" and "licence does not authorise this deployment shape".
 *
 * PURE and dependency-free on purpose (GMS and DMS keep their own copies of the same table): it reads no clock, no environment, no database.
 *
 *   LICENSE_REQUIRED false                                     licensed (today's behaviour)
 *   required, no verified licence (unconfigured / unknown)     NO_LICENSE
 *   required, licence does not list this deployment shape      MODE_NOT_LICENSED
 *   otherwise                                                  licensed (expiry is then the state function's business)
 */
import type { LicenseState } from './state.js';

export type LicenseReason = 'NO_LICENSE' | 'MODE_NOT_LICENSED';
export type DeploymentMode = 'sso' | 'standalone';

export interface Entitlement {
  licensed: boolean;
  reason: LicenseReason | null;
}

/** A token or record with no `modes` (or an empty list) authorises the shape every deployment has had so far: behind SSO. */
export function effectiveModes(modes: readonly string[] | null | undefined): string[] {
  return modes && modes.length > 0 ? [...modes] : ['sso'];
}

export function computeEntitlement(input: {
  required: boolean;
  state: LicenseState;
  modes: readonly string[] | null | undefined;
  deployment: DeploymentMode;
}): Entitlement {
  if (!input.required) return { licensed: true, reason: null };
  if (input.state === 'unconfigured' || input.state === 'unknown') return { licensed: false, reason: 'NO_LICENSE' };
  if (!effectiveModes(input.modes).includes(input.deployment)) return { licensed: false, reason: 'MODE_NOT_LICENSED' };
  return { licensed: true, reason: null };
}
