/**
 * The admin Users list: search plus filters by status, source, client and role.
 *
 * Roles and client access do not live on the user. They hang off groups:
 *  - a user's access is the union of the groups they belong to (every local user
 *    has a personal group `CN=user:<id>`, plus any shared groups);
 *  - reaching a client (`edams`, `gms`) needs a group with an entitlement row for
 *    it, OR the client has no entitlement rows at all (open to everyone). That is
 *    exactly the rule the portal launcher uses (portal/catalog.ts's entitled()),
 *    so this filter can never disagree with what the user actually sees;
 *  - a GMS role is, in order of precedence, the user's own per-user grant
 *    (idp_client_user_roles) and otherwise the mapping of one of their groups
 *    (idp_gms_role_mappings), the same order auth/client-role-claims.ts resolves;
 *  - a DMS role is mapped in DMS's own database (idp_role_mappings), so the
 *    caller first asks DMS which groups carry that role and passes them in.
 *
 * Pure: builds SQL text and parameters, touches nothing, so the combinations can
 * be tested without a database. The platform administrator is excluded by
 * construction and no combination of filters can bring it back.
 */

export const USER_STATUS_FILTERS = ['active', 'inactive'] as const;
export type UserStatusFilter = (typeof USER_STATUS_FILTERS)[number];

export const USER_SOURCE_FILTERS = ['local', 'ad'] as const;
export type UserSourceFilter = (typeof USER_SOURCE_FILTERS)[number];

/** Two-factor sign-in: has the person enrolled an authenticator app. */
export const USER_MFA_FILTERS = ['enrolled', 'not_enrolled'] as const;
export type UserMfaFilter = (typeof USER_MFA_FILTERS)[number];

export const USER_SORTS = ['email', 'name', 'status', 'last_login', 'created'] as const;
export type UserSort = (typeof USER_SORTS)[number];

/**
 * ORDER BY for the Users list. The column comes from a fixed map, never from the request text, so a crafted `sort` cannot reach the
 * SQL; an unknown value falls back to the email. The email is always the final tie-break so paging is stable.
 */
export function userOrderBy(sort: unknown, dir: unknown): string {
  const column: Record<UserSort, string> = {
    email: 'u.email',
    name: "lower(coalesce(u.family_name, '') || ' ' || coalesce(u.given_name, ''))",
    status: 'u.is_active',
    last_login: 'u.last_login_at',
    created: 'u.created_at',
  };
  const key = (USER_SORTS as readonly string[]).includes(String(sort)) ? (String(sort) as UserSort) : 'email';
  const direction = String(dir).toLowerCase() === 'desc' ? 'DESC' : 'ASC';
  const nulls = key === 'last_login' ? ' NULLS LAST' : '';
  return key === 'email' ? `u.email ${direction}` : `${column[key]} ${direction}${nulls}, u.email ASC`;
}

/** `idp:admin` | `dms:<ROLE>` | `gms:<role>`. */
export interface ParsedRoleFilter {
  system: 'idp' | 'dms' | 'gms';
  role: string;
}

export function parseRoleFilter(raw: unknown): ParsedRoleFilter | null {
  if (typeof raw !== 'string' || !raw) return null;
  const i = raw.indexOf(':');
  if (i < 1) return null;
  const system = raw.slice(0, i);
  const role = raw.slice(i + 1).trim();
  if (!role || role.length > 64 || !/^[A-Za-z0-9_]+$/.test(role)) return null;
  if (system === 'idp' || system === 'dms' || system === 'gms') return { system, role };
  return null;
}

export interface UserListFilterInput {
  q?: string;
  status?: string;
  source?: string;
  mfa?: string;
  /** A client_id from the live client seed, or empty. `portal` is open to everyone and adds no filter. */
  client?: string;
  role?: ParsedRoleFilter | null;
  /** Group DNs DMS reports as carrying the requested DMS role (required when role.system === 'dms'). */
  dmsGroupDns?: string[];
  /** IDP_CONFIG.adminGroup, for the `idp:admin` filter. */
  adminGroup: string;
}

export interface UserListFilter {
  /** A complete `WHERE ...` clause over `idp_users u`, always present. */
  where: string;
  params: unknown[];
}

export function buildUserListFilter(input: UserListFilterInput): UserListFilter {
  const params: unknown[] = [];
  const add = (v: unknown): string => {
    params.push(v);
    return `$${params.length}`;
  };
  const clauses: string[] = ['NOT u.is_platform_admin'];

  const q = (input.q ?? '').trim();
  if (q) clauses.push(`u.email ILIKE '%' || ${add(q)} || '%'`);

  if (input.status === 'active') clauses.push('u.is_active = TRUE');
  else if (input.status === 'inactive') clauses.push('u.is_active = FALSE');

  if (input.source === 'local' || input.source === 'ad') clauses.push(`u.source = ${add(input.source)}`);

  if (input.mfa === 'enrolled') clauses.push('u.totp_enabled = TRUE');
  else if (input.mfa === 'not_enrolled') clauses.push('u.totp_enabled = FALSE');

  if (input.client && input.client !== 'portal') {
    const c = add(input.client);
    clauses.push(
      `(NOT EXISTS (SELECT 1 FROM idp_app_entitlements WHERE relying_party = ${c})
        OR EXISTS (SELECT 1 FROM idp_user_groups ug
                     JOIN idp_app_entitlements e ON e.group_dn = ug.group_dn
                    WHERE ug.user_id = u.id AND e.relying_party = ${c}))`,
    );
  }

  const role = input.role;
  if (role) {
    if (role.system === 'idp') {
      clauses.push(`EXISTS (SELECT 1 FROM idp_user_groups ug WHERE ug.user_id = u.id AND ug.group_dn = ${add(input.adminGroup)})`);
    } else if (role.system === 'gms') {
      const r = add(role.role);
      clauses.push(
        `(EXISTS (SELECT 1 FROM idp_client_user_roles cr
                   WHERE cr.email = lower(u.email) AND cr.client_id = 'gms' AND cr.role_name = ${r})
          OR (NOT EXISTS (SELECT 1 FROM idp_client_user_roles cr
                           WHERE cr.email = lower(u.email) AND cr.client_id = 'gms')
              AND EXISTS (SELECT 1 FROM idp_user_groups ug
                            JOIN idp_gms_role_mappings m ON m.group_dn = ug.group_dn
                           WHERE ug.user_id = u.id AND m.role_name = ${r})))`,
      );
    } else {
      const dns = input.dmsGroupDns ?? [];
      // No group carries this DMS role: nobody does. An empty ANY() would be a type error.
      clauses.push(
        dns.length === 0
          ? 'FALSE'
          : `EXISTS (SELECT 1 FROM idp_user_groups ug WHERE ug.user_id = u.id AND ug.group_dn = ANY(${add(dns)}::text[]))`,
      );
    }
  }

  return { where: `WHERE ${clauses.join('\n  AND ')}`, params };
}
