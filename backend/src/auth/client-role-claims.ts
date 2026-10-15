/**
 * Client-scoped role claims (directive §6.3).
 *
 * Resolves coarse application roles and surfaces them as additive OIDC
 * claims / bridge-session input. Resolution precedence for GMS is: an
 * explicit per-user grant (idp_client_user_roles, most specific) > AD
 * group→role mapping (idp_gms_role_mappings) > default `guest`. Local
 * GMS/DMS role tables are not touched here — GMS's own login precedence
 * (auth.service.ts issueSsoSession) is what decides whether a resolved
 * role here actually wins over GMS's local cache for a given login.
 */

import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { resolveEdamsRolesForGroups } from '../admin/dms-internal-client.js';
import { getGrantedRoles } from './client-user-roles.js';
import { logger } from '../logging/logger.js';
import { CircuitBreaker, CircuitOpenError } from '../infrastructure/circuitBreaker.js';

/**
 * Guards the DMS role lookup that runs inside every token issuance. With DMS down, each sign-in used to wait the full
 * DMS_INTERNAL_TIMEOUT_MS before being answered without DMS roles; after three failures in a row the breaker answers at once for
 * 30 s (omitting the claim exactly as a failed call does), then lets one trial through. See infrastructure/circuitBreaker.ts.
 */
export const dmsRolesBreaker = new CircuitBreaker({ name: 'dms-roles', failureThreshold: 3, openMs: 30_000 });

/** Namespaced claims — same style as AD_GROUPS_CLAIM. */
export const GMS_ROLES_CLAIM = 'https://gms.examplecorp.com/roles';
export const EDAMS_ROLES_CLAIM = 'https://edams.examplecorp.com/roles';

const DEFAULT_GMS_ROLE = 'guest';
const DEFAULT_EDAMS_ROLE = 'EMPLOYEE';

/**
 * Resolve GMS staff role(s) for one identity: explicit per-user grant first,
 * then AD group mapping, then the `guest` default.
 */
export async function resolveGmsRoles(email: string, groups: string[]): Promise<string[]> {
  const granted = await getGrantedRoles(email, 'gms');
  if (granted.length > 0) return granted;
  return resolveGmsRolesFromGroups(groups);
}

/** Map IdP group DNs to GMS staff role names via SSO-owned mappings. */
export async function resolveGmsRolesFromGroups(groups: string[]): Promise<string[]> {
  if (groups.length === 0) return [DEFAULT_GMS_ROLE];
  const { rows } = await pool.query<{ role_name: string }>(
    'SELECT DISTINCT role_name FROM idp_gms_role_mappings WHERE group_dn = ANY($1) ORDER BY role_name ASC',
    [groups],
  );
  const roles = rows.map((row) => row.role_name);
  return roles.length ? roles : [DEFAULT_GMS_ROLE];
}

/**
 * Map IdP group DNs to DMS coarse roles via DMS's owned mapping table
 * (HTTP internal API — no foreign DB).
 *
 * Returns `null` for "I could not resolve this", as distinct from an array for
 * "I resolved it, and this is the answer".
 *
 * WHY THAT DISTINCTION MATTERS: this used to return `[DEFAULT_EDAMS_ROLE]` for
 * FOUR different situations — the user genuinely maps to nothing, the internal
 * API key is unset, DMS is unreachable, and DMS explicitly answered EMPLOYEE.
 * The first and last are real answers; the middle two are failures wearing a
 * real answer's clothes. DMS treats a non-empty roles claim as AUTHORITATIVE
 * over its own local `user_roles` table (see DMS auth.routes.ts's callback:
 * `if (claimRoles.length > 0) allRoles = claimRoles`), so a momentary blip in
 * DMS's own internal API caused SSO to assert "this person is an EMPLOYEE",
 * and DMS believed it over the correct role sitting in its own database —
 * silently demoting whoever logged in during the blip, for their whole
 * session, with only a warn-level log line anywhere.
 *
 * Emitting nothing instead lets DMS's existing fallback chain (claim → local
 * user_roles → AD-group mapping → EMPLOYEE) do exactly what it was written to
 * do. Omission is the honest signal; a fabricated default is not.
 */
export async function resolveEdamsRolesFromGroups(groups: string[]): Promise<string[] | null> {
  // A real, resolved answer: this identity is in no groups, so nothing maps.
  if (groups.length === 0) return [DEFAULT_EDAMS_ROLE];
  // Not an answer: we were never given the credential needed to ask.
  if (!IDP_CONFIG.dmsInternalApiKey) {
    logger.error(
      '[idp:claims:ALERT] DMS_INTERNAL_API_KEY is unset — omitting the DMS roles claim so DMS falls back to its own role table. DMS-side role mappings are NOT being applied.',
    );
    return null;
  }

  try {
    const roles = await dmsRolesBreaker.run(() => resolveEdamsRolesForGroups(IDP_CONFIG.dmsDefaultTenant, groups));
    // An empty array here IS an answer: DMS looked and nothing mapped.
    return roles.length ? roles : [DEFAULT_EDAMS_ROLE];
  } catch (err) {
    if (err instanceof CircuitOpenError) {
      // The failures that opened the breaker were each logged at error below; repeating that for every sign-in while it is open
      // would bury the log, so these are debug.
      logger.debug({ retryInMs: err.retryInMs }, '[idp:claims] DMS role lookup paused by the circuit breaker; omitting the DMS roles claim');
      return null;
    }
    // error, not warn: this silently changes the authorization outcome of a
    // live login, and there is no alerting pipeline that would catch a warn.
    logger.error(
      { err, groupCount: groups.length },
      '[idp:claims:ALERT] DMS role resolve failed — omitting the DMS roles claim; DMS will fall back to its own role table for this login',
    );
    return null;
  }
}

export interface ClientRoleClaims {
  [GMS_ROLES_CLAIM]: string[];
  /** `null` when DMS role resolution failed — the claim is then omitted entirely
   *  rather than asserted as a default. See resolveEdamsRolesFromGroups. */
  [EDAMS_ROLES_CLAIM]: string[] | null;
}

/** Resolve both client-scoped role arrays for an identity. */
export async function resolveClientRoleClaims(email: string, groups: string[]): Promise<ClientRoleClaims> {
  const [gmsRoles, edamsRoles] = await Promise.all([
    resolveGmsRoles(email, groups),
    resolveEdamsRolesFromGroups(groups),
  ]);
  return {
    [GMS_ROLES_CLAIM]: gmsRoles,
    [EDAMS_ROLES_CLAIM]: edamsRoles,
  };
}
