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
 * (HTTP internal API — no foreign DB). Degrades to the EMPLOYEE default when
 * the key is unset or DMS is unreachable so token issuance never fails open
 * or hard-fails login.
 */
export async function resolveEdamsRolesFromGroups(groups: string[]): Promise<string[]> {
  if (groups.length === 0) return [DEFAULT_EDAMS_ROLE];
  if (!IDP_CONFIG.dmsInternalApiKey) return [DEFAULT_EDAMS_ROLE];

  try {
    const roles = await resolveEdamsRolesForGroups(IDP_CONFIG.dmsDefaultTenant, groups);
    return roles.length ? roles : [DEFAULT_EDAMS_ROLE];
  } catch (err) {
    logger.warn({ err }, '[idp:claims] DMS role resolve failed — emitting default EMPLOYEE');
    return [DEFAULT_EDAMS_ROLE];
  }
}

export interface ClientRoleClaims {
  [GMS_ROLES_CLAIM]: string[];
  [EDAMS_ROLES_CLAIM]: string[];
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
