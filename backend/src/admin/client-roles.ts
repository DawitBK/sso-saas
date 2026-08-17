/**
 * Client-scoped role catalog (directive §6.3).
 *
 * Reads from `idp_client_roles`. Falls back to the historical hardcoded lists
 * if the catalog table is empty or unreachable, so admin UI keeps working
 * during migrate/boot races.
 */

import { pool } from '../db/pool.js';

export interface ClientRole {
  clientId: string;
  roleName: string;
  displayName: string;
  officeScoped: boolean;
  sortOrder: number;
}

/** Historical fallback — kept in sync with GMS STAFF_ROLES (guest excluded). */
export const GMS_ROLES_FALLBACK = [
  'super_admin',
  'admin',
  'super_reception',
  'reception',
  'super_host',
  'host',
] as const;

export const GMS_OFFICE_SCOPED_FALLBACK = ['admin', 'reception', 'host'] as const;

export const DMS_ROLES_FALLBACK = [
  'SYSTEM_ADMIN',
  'DEPT_MANAGER',
  'RECORDS_OFFICER',
  'APPROVER',
  'EMPLOYEE',
  'AUDITOR',
  'EXECUTIVE',
] as const;

async function listClientRoles(clientId: string): Promise<ClientRole[]> {
  const { rows } = await pool.query<{
    client_id: string;
    role_name: string;
    display_name: string;
    office_scoped: boolean;
    sort_order: number;
  }>(
    `SELECT client_id, role_name, display_name, office_scoped, sort_order
       FROM idp_client_roles
      WHERE client_id = $1
      ORDER BY sort_order ASC, role_name ASC`,
    [clientId],
  );
  return rows.map((r) => ({
    clientId: r.client_id,
    roleName: r.role_name,
    displayName: r.display_name,
    officeScoped: r.office_scoped,
    sortOrder: r.sort_order,
  }));
}

export async function listGmsRoleNames(): Promise<string[]> {
  try {
    const roles = await listClientRoles('gms');
    if (roles.length > 0) return roles.map((r) => r.roleName);
  } catch {
    // table may not exist yet during first boot before migrate finishes
  }
  return [...GMS_ROLES_FALLBACK];
}

export async function listGmsOfficeScopedRoleNames(): Promise<string[]> {
  try {
    const roles = await listClientRoles('gms');
    if (roles.length > 0) return roles.filter((r) => r.officeScoped).map((r) => r.roleName);
  } catch {
    // fall through
  }
  return [...GMS_OFFICE_SCOPED_FALLBACK];
}

export async function listDmsRoleNames(): Promise<string[]> {
  try {
    const roles = await listClientRoles('edams');
    if (roles.length > 0) return roles.map((r) => r.roleName);
  } catch {
    // fall through
  }
  return [...DMS_ROLES_FALLBACK];
}
