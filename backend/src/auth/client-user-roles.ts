/**
 * Per-user client-scoped role grants (directive §6.3 follow-up to
 * idp_client_roles / migration 009). This is the "grant a role directly to
 * one person" mechanism the AD-group mapping (idp_gms_role_mappings) can't
 * express — an admin action, or a first-run backfill, writes here; role
 * resolution at login reads it before falling back to group mapping.
 */

import { pool } from '../db/pool.js';

export interface ClientUserRoleGrant {
  email: string;
  clientId: string;
  roleName: string;
  grantedBy: string;
  grantedAt: string;
}

/**
 * Current per-user grants for one user + client. An empty array means "no
 * explicit grant" — resolution falls through to group mapping / default,
 * same as if the row never existed. There is no separate "explicitly zero
 * roles" state: revoking every grant is exactly the same as never granting
 * one, which is the simpler and more useful semantic (it re-exposes
 * whatever the group mapping or default would otherwise say).
 */
export async function getGrantedRoles(email: string, clientId: string): Promise<string[]> {
  const { rows } = await pool.query<{ role_name: string }>(
    'SELECT role_name FROM idp_client_user_roles WHERE email = $1 AND client_id = $2 ORDER BY role_name ASC',
    [email.toLowerCase(), clientId],
  );
  return rows.map((r) => r.role_name);
}

/**
 * Replace this user's entire grant set for a client — matches GMS's own
 * admin endpoint semantics (`PATCH /:id/roles` replaces the whole set, not
 * an incremental add/remove). Validates every role name against the
 * `idp_client_roles` catalog for this client before writing anything.
 */
export async function setGrantedRoles(
  email: string,
  clientId: string,
  roles: string[],
  grantedBy: string,
): Promise<void> {
  const normalizedEmail = email.toLowerCase();
  const uniqueRoles = Array.from(new Set(roles));

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (uniqueRoles.length > 0) {
      const { rows: valid } = await client.query<{ role_name: string }>(
        'SELECT role_name FROM idp_client_roles WHERE client_id = $1 AND role_name = ANY($2)',
        [clientId, uniqueRoles],
      );
      const validNames = new Set(valid.map((r) => r.role_name));
      const unknown = uniqueRoles.filter((r) => !validNames.has(r));
      if (unknown.length > 0) {
        throw new Error(`Unknown role(s) for client "${clientId}": ${unknown.join(', ')}`);
      }
    }

    await client.query(
      'DELETE FROM idp_client_user_roles WHERE email = $1 AND client_id = $2',
      [normalizedEmail, clientId],
    );

    for (const roleName of uniqueRoles) {
      await client.query(
        `INSERT INTO idp_client_user_roles (email, client_id, role_name, granted_by)
         VALUES ($1, $2, $3, $4)`,
        [normalizedEmail, clientId, roleName, grantedBy],
      );
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** List every per-user grant for a client (admin console listing). */
export async function listGrantedRolesForClient(clientId: string): Promise<ClientUserRoleGrant[]> {
  const { rows } = await pool.query<{
    email: string;
    client_id: string;
    role_name: string;
    granted_by: string;
    granted_at: string;
  }>(
    'SELECT email, client_id, role_name, granted_by, granted_at FROM idp_client_user_roles WHERE client_id = $1 ORDER BY email ASC, role_name ASC',
    [clientId],
  );
  return rows.map((r) => ({
    email: r.email,
    clientId: r.client_id,
    roleName: r.role_name,
    grantedBy: r.granted_by,
    grantedAt: r.granted_at,
  }));
}
