/**
 * Roles of the applications that sign in through this IdP and are managed from its console.
 *
 * An application is MANAGED when its role catalog (idp_client_roles) has rows and it is not one of the systems that have their own
 * flows: DMS ("edams") and GMS ("gms") apply their roles through their internal APIs and the bridge, and the portal and the console
 * itself are not applications. For a managed application:
 *
 *  - the person's roles are the per-user grants (idp_client_user_roles), set on the person's App access panel in the console;
 *  - no grant means no access: the sign-in is refused here (interactions/router.ts) and the launcher does not show the tile;
 *  - the application receives the grants in the `app_roles` claim (scope `app_roles`, only for the client that asked) and applies
 *    them at every sign-in, so a change made in the console is in force at the person's next sign-in.
 *
 * The catalog itself is data: seeded from CLIENT_ROLES_JSON (oidc/client-roles-config.ts) and edited on the client's page.
 */

import { pool } from '../db/pool.js';
import { getGrantedRoles } from './client-user-roles.js';

export const APP_ROLES_CLAIM = 'app_roles';
export const APP_ROLES_SCOPE = 'app_roles';

/** Clients that have their own role flows or are not applications; never managed through this module. */
export const NOT_MANAGED_CLIENTS = new Set(['edams', 'gms', 'portal', 'idp-admin']);

const CACHE_MS = 3000;
let cache: { at: number; ids: Set<string> } | null = null;

/** Forget the cached list of managed clients (after the catalog changes, and in tests). */
export function resetManagedClientsCache(): void {
  cache = null;
}

/**
 * Let a client ask for the `app_roles` claim. A client with no scope allowlist (NULL or empty) is unrestricted and needs nothing; one
 * whose allowlist was set before it became managed gets the scope appended, once. An operator's narrower list is otherwise left alone.
 */
export async function ensureAppRolesScope(clientId: string): Promise<void> {
  await pool.query(
    `UPDATE idp_clients SET scope = scope || ' ' || $2, updated_at = NOW()
      WHERE client_id = $1 AND scope IS NOT NULL AND scope <> ''
        AND NOT (string_to_array(scope, ' ') @> ARRAY[$2]::text[])`,
    [clientId, APP_ROLES_SCOPE],
  );
}

/** The ids of the managed applications: those with at least one role in the catalog. Cached for a few seconds. */
export async function managedClientIds(): Promise<Set<string>> {
  if (cache && Date.now() - cache.at < CACHE_MS) return cache.ids;
  const { rows } = await pool.query<{ client_id: string }>('SELECT DISTINCT client_id FROM idp_client_roles');
  const ids = new Set(rows.map((r) => r.client_id).filter((id) => !NOT_MANAGED_CLIENTS.has(id)));
  cache = { at: Date.now(), ids };
  return ids;
}

export async function isRoleManagedClient(clientId: string): Promise<boolean> {
  return (await managedClientIds()).has(clientId);
}

/**
 * The roles this person holds in a managed application: their grants, possibly none. `undefined` when the client is not managed
 * (so the claim is then left out entirely, as for every other client).
 */
export async function appRolesFor(email: string, clientId: string): Promise<string[] | undefined> {
  if (!(await isRoleManagedClient(clientId))) return undefined;
  return getGrantedRoles(email, clientId);
}

/**
 * May this account open this application? Always for an application that is not managed; for a managed one only an active account
 * that holds at least one of its roles.
 */
export async function accountHasAppAccess(accountId: string, clientId: string): Promise<boolean> {
  if (!(await isRoleManagedClient(clientId))) return true;
  const { rows } = await pool.query<{ email: string; is_active: boolean }>('SELECT email, is_active FROM idp_users WHERE id = $1', [accountId]);
  const user = rows[0];
  if (!user || !user.is_active) return false;
  return (await getGrantedRoles(user.email, clientId)).length > 0;
}

/** Every managed application this person may open, with their roles in each (the console's App access panel and the launcher). */
export async function appAccessOf(email: string): Promise<Record<string, string[]>> {
  const ids = [...(await managedClientIds())];
  if (ids.length === 0) return {};
  const { rows } = await pool.query<{ client_id: string; role_name: string }>(
    'SELECT client_id, role_name FROM idp_client_user_roles WHERE email = $1 AND client_id = ANY($2) ORDER BY client_id, role_name',
    [email.toLowerCase(), ids],
  );
  const out: Record<string, string[]> = Object.fromEntries(ids.map((id) => [id, [] as string[]]));
  for (const r of rows) out[r.client_id]!.push(r.role_name);
  return out;
}

export interface ManagedClientCatalog {
  clientId: string;
  name: string;
  roles: { roleName: string; displayName: string; sortOrder: number }[];
}

/** The role catalog of every managed application, with the application's display name (the console reads this to draw the panel). */
export async function managedCatalog(): Promise<ManagedClientCatalog[]> {
  const ids = [...(await managedClientIds())];
  if (ids.length === 0) return [];
  const [{ rows: roleRows }, { rows: clientRows }] = await Promise.all([
    pool.query<{ client_id: string; role_name: string; display_name: string; sort_order: number }>(
      'SELECT client_id, role_name, display_name, sort_order FROM idp_client_roles WHERE client_id = ANY($1) ORDER BY client_id, sort_order, role_name',
      [ids],
    ),
    pool.query<{ client_id: string; name: string }>('SELECT client_id, name FROM idp_clients WHERE client_id = ANY($1)', [ids]),
  ]);
  const names = new Map(clientRows.map((c) => [c.client_id, c.name]));
  return ids
    .map((clientId) => ({
      clientId,
      name: names.get(clientId) ?? clientId,
      roles: roleRows
        .filter((r) => r.client_id === clientId)
        .map((r) => ({ roleName: r.role_name, displayName: r.display_name || r.role_name, sortOrder: r.sort_order })),
    }))
    .sort((a, b) => a.name.localeCompare(b.name));
}
