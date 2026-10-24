/**
 * The role catalog of the applications managed from the console (auth/app-roles.ts), seeded from the environment.
 *
 *   CLIENT_ROLES_JSON   { "<client id>": [ { "name": "cashier", "display_name": "Cashier", "sort_order": 40 }, ... ], ... }
 *
 * Absent or empty means no application is managed. The list only ever ADDS: a role that is missing from idp_client_roles is inserted, a role
 * that is there is left exactly as it is (an administrator may have renamed or reordered it on the client's page), and nothing is deleted. The
 * built-in systems (DMS, GMS) and the portal cannot be listed: they have their own role flows. A malformed list is a startup error.
 */

import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';
import { ensureAppRolesScope, NOT_MANAGED_CLIENTS, resetManagedClientsCache } from '../auth/app-roles.js';

export interface SeedRole {
  name: string;
  displayName: string;
  sortOrder: number;
}

const CLIENT_ID_RE = /^[a-z0-9][a-z0-9_-]{1,63}$/;
export const ROLE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

export function parseClientRoles(raw: string | undefined): Map<string, SeedRole[]> {
  const out = new Map<string, SeedRole[]>();
  if (raw === undefined || raw.trim() === '') return out;
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error('CLIENT_ROLES_JSON is not valid JSON');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('CLIENT_ROLES_JSON must be a JSON object: client id -> list of roles');
  for (const [clientId, list] of Object.entries(value as Record<string, unknown>)) {
    const where = `CLIENT_ROLES_JSON["${clientId}"]`;
    if (!CLIENT_ID_RE.test(clientId)) throw new Error(`${where}: the key must be a client id (lower-case letters, digits, "-" or "_")`);
    if (NOT_MANAGED_CLIENTS.has(clientId)) throw new Error(`${where}: "${clientId}" has its own role flow and cannot be listed here`);
    if (!Array.isArray(list) || list.length === 0) throw new Error(`${where}: must be a non-empty list of roles`);
    const seen = new Set<string>();
    const roles = list.map((entry, i) => {
      const r = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
      if (typeof r.name !== 'string' || !ROLE_NAME_RE.test(r.name)) throw new Error(`${where}[${i}]: name must be letters, digits, "_", "-" or "." (1 to 64 characters)`);
      if (seen.has(r.name)) throw new Error(`${where}[${i}]: role "${r.name}" is listed twice`);
      seen.add(r.name);
      if (r.display_name !== undefined && (typeof r.display_name !== 'string' || r.display_name.trim() === '' || r.display_name.length > 80)) {
        throw new Error(`${where}[${i}]: display_name must be 1 to 80 characters`);
      }
      if (r.sort_order !== undefined && !Number.isInteger(r.sort_order)) throw new Error(`${where}[${i}]: sort_order must be a whole number`);
      return {
        name: r.name,
        displayName: typeof r.display_name === 'string' ? r.display_name.trim() : r.name,
        sortOrder: typeof r.sort_order === 'number' ? r.sort_order : (i + 1) * 10,
      };
    });
    out.set(clientId, roles);
  }
  return out;
}

/** Insert the configured roles that are missing, and make sure each managed client may ask for the `app_roles` claim. */
export async function seedClientRoles(raw: string | undefined = process.env.CLIENT_ROLES_JSON): Promise<void> {
  const configured = parseClientRoles(raw);
  for (const [clientId, roles] of configured) {
    for (const r of roles) {
      await pool.query(
        `INSERT INTO idp_client_roles (client_id, role_name, display_name, office_scoped, sort_order)
         VALUES ($1, $2, $3, FALSE, $4)
         ON CONFLICT (client_id, role_name) DO NOTHING`,
        [clientId, r.name, r.displayName, r.sortOrder],
      );
    }
    await ensureAppRolesScope(clientId);
  }
  resetManagedClientsCache();
  if (configured.size > 0) logger.info({ clients: [...configured.keys()] }, '[idp:roles] role catalogs seeded for the applications managed from the console');
}
