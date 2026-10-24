/**
 * The role catalog of an application, as the client's page edits it (admin > Clients > the application > Roles).
 *
 * The catalog says which roles can be given to a person for that application (the App access panel offers exactly these) and what each is
 * called. The application itself decides what a role name means: a name it does not recognise changes nothing there, so adding a role here
 * never grants anything by itself. Removing a role that someone still holds is refused, so access is never lost as a side effect of tidying.
 *
 * DMS ("edams") and GMS ("gms") have their own role flows and their catalogs are not edited here; neither are the portal and the console.
 */

import { pool } from '../db/pool.js';
import { ensureAppRolesScope, NOT_MANAGED_CLIENTS, resetManagedClientsCache } from '../auth/app-roles.js';
import { ROLE_NAME_RE } from '../oidc/client-roles-config.js';

export interface CatalogRole {
  roleName: string;
  displayName: string;
  sortOrder: number;
  /** How many people hold it. */
  holders: number;
}

/** The roles of one client with how many people hold each (read-only for DMS and GMS). */
export async function clientCatalog(clientId: string): Promise<CatalogRole[]> {
  const { rows } = await pool.query<{ role_name: string; display_name: string; sort_order: number; holders: string }>(
    `SELECT r.role_name, r.display_name, r.sort_order,
            (SELECT COUNT(*) FROM idp_client_user_roles g WHERE g.client_id = r.client_id AND g.role_name = r.role_name) AS holders
       FROM idp_client_roles r
      WHERE r.client_id = $1
      ORDER BY r.sort_order, r.role_name`,
    [clientId],
  );
  return rows.map((r) => ({ roleName: r.role_name, displayName: r.display_name || r.role_name, sortOrder: r.sort_order, holders: Number(r.holders) }));
}

/** Can this client's catalog be edited from the console? */
export const catalogEditable = (clientId: string): boolean => !NOT_MANAGED_CLIENTS.has(clientId);

export interface CatalogEdit {
  roleName: string;
  displayName?: string;
  sortOrder?: number;
}

export type CatalogResult =
  | { ok: true; before: CatalogRole[]; after: CatalogRole[] }
  | { ok: false; status: number; code: string; message: string };

/** Replace a client's catalog with the given list: roles in the list are added or updated, roles missing from it are removed if nobody holds them. */
export async function replaceClientCatalog(clientId: string, raw: unknown): Promise<CatalogResult> {
  if (!catalogEditable(clientId)) {
    return { ok: false, status: 409, code: 'ERR-CATALOG-PROTECTED', message: 'This application has its own role flow; its roles are not edited here.' };
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    return { ok: false, status: 400, code: 'ERR-VALIDATION-FAILED', message: 'Give at least one role. To stop managing the application’s access, remove it from the deployment settings.' };
  }
  const wanted: Required<CatalogEdit>[] = [];
  const seen = new Set<string>();
  for (const [i, entry] of raw.entries()) {
    const r = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
    if (typeof r.roleName !== 'string' || !ROLE_NAME_RE.test(r.roleName)) {
      return { ok: false, status: 400, code: 'ERR-VALIDATION-FAILED', message: `Role ${i + 1}: the name must be letters, digits, "_", "-" or "." (1 to 64 characters).` };
    }
    if (seen.has(r.roleName)) return { ok: false, status: 400, code: 'ERR-VALIDATION-FAILED', message: `The role "${r.roleName}" is listed twice.` };
    seen.add(r.roleName);
    const displayName = typeof r.displayName === 'string' && r.displayName.trim() !== '' ? r.displayName.trim() : r.roleName;
    if (displayName.length > 80) return { ok: false, status: 400, code: 'ERR-VALIDATION-FAILED', message: `Role "${r.roleName}": the display name is at most 80 characters.` };
    if (r.sortOrder !== undefined && !Number.isInteger(r.sortOrder)) return { ok: false, status: 400, code: 'ERR-VALIDATION-FAILED', message: `Role "${r.roleName}": the order must be a whole number.` };
    wanted.push({ roleName: r.roleName, displayName, sortOrder: typeof r.sortOrder === 'number' ? r.sortOrder : (i + 1) * 10 });
  }

  const { rows: exists } = await pool.query('SELECT 1 FROM idp_clients WHERE client_id = $1', [clientId]);
  if (exists.length === 0) return { ok: false, status: 404, code: 'ERR-CLIENT-NOT-FOUND', message: 'No such application.' };

  const before = await clientCatalog(clientId);
  const removed = before.filter((b) => !seen.has(b.roleName));
  const heldRemoved = removed.filter((b) => b.holders > 0);
  if (heldRemoved.length > 0) {
    return {
      ok: false,
      status: 409,
      code: 'ERR-ROLE-IN-USE',
      message: `Cannot remove ${heldRemoved.map((b) => `"${b.roleName}" (${b.holders} ${b.holders === 1 ? 'person holds' : 'people hold'} it)`).join(', ')}. Change those people’s access first.`,
    };
  }

  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    for (const r of wanted) {
      await db.query(
        `INSERT INTO idp_client_roles (client_id, role_name, display_name, office_scoped, sort_order)
         VALUES ($1, $2, $3, FALSE, $4)
         ON CONFLICT (client_id, role_name) DO UPDATE SET display_name = EXCLUDED.display_name, sort_order = EXCLUDED.sort_order`,
        [clientId, r.roleName, r.displayName, r.sortOrder],
      );
    }
    if (removed.length > 0) {
      await db.query('DELETE FROM idp_client_roles WHERE client_id = $1 AND role_name = ANY($2)', [clientId, removed.map((b) => b.roleName)]);
    }
    await db.query('COMMIT');
  } catch (err) {
    await db.query('ROLLBACK');
    throw err;
  } finally {
    db.release();
  }
  await ensureAppRolesScope(clientId);
  resetManagedClientsCache();
  return { ok: true, before, after: await clientCatalog(clientId) };
}
