/**
 * Turns the query string of the Users list (and its CSV export) into one filter, so the page, the export and any future caller
 * cannot disagree about who is in "the current list". Unknown filter values are ignored, never an error, so a stale link still opens.
 */
import { IDP_CONFIG } from '../../config.js';
import { DmsInternalApiError, listDmsGroupsForRole } from '../dms-internal-client.js';
import {
  buildUserListFilter,
  parseRoleFilter,
  USER_MFA_FILTERS,
  USER_SORTS,
  USER_SOURCE_FILTERS,
  USER_STATUS_FILTERS,
  userOrderBy,
  type UserListFilter,
} from './user-filters.js';

export interface ResolvedUserQuery {
  filter: UserListFilter;
  orderBy: string;
  /** What was understood, echoed to the page so it can show the active filters. */
  view: { q: string; status: string; source: string; mfa: string; client: string; role: string; sort: string; dir: 'asc' | 'desc' };
}

export type UserQueryResult = ({ ok: true } & ResolvedUserQuery) | { ok: false; status: number; code: string; message: string };

const pick = (allowed: readonly string[], value: unknown): string => (allowed.includes(String(value)) ? String(value) : '');

export async function resolveUserListQuery(query: Record<string, unknown>, requestId: string): Promise<UserQueryResult> {
  const q = String(query.q ?? '').trim();
  const status = pick(USER_STATUS_FILTERS, query.status);
  const source = pick(USER_SOURCE_FILTERS, query.source);
  const mfa = pick(USER_MFA_FILTERS, query.mfa);
  const clientFilter = String(query.client ?? '');
  const client = IDP_CONFIG.clientSeed.some((c) => c.client_id === clientFilter) ? clientFilter : '';
  const role = parseRoleFilter(query.role);
  const sort = pick(USER_SORTS, query.sort) || 'email';
  const dir = String(query.dir).toLowerCase() === 'desc' ? 'desc' : 'asc';

  // DMS roles are mapped in DMS's own database, so DMS says which groups carry the role. If it cannot answer, say so: a silently
  // empty or unfiltered list would be wrong in a way nobody could see.
  let dmsGroupDns: string[] | undefined;
  if (role?.system === 'dms') {
    try {
      dmsGroupDns = await listDmsGroupsForRole(IDP_CONFIG.dmsDefaultTenant, role.role, requestId);
    } catch (err) {
      return {
        ok: false,
        status: err instanceof DmsInternalApiError ? 502 : 503,
        code: 'ERR-DMS-ROLE-FILTER',
        message: 'Could not ask DMS who holds that role, so the list cannot be filtered by it. Try again, or filter by something else.',
      };
    }
  }

  const filter = buildUserListFilter({ q, status, source, mfa, client, role, dmsGroupDns, adminGroup: IDP_CONFIG.adminGroup });
  return {
    ok: true,
    filter,
    orderBy: userOrderBy(sort, dir),
    view: { q, status, source, mfa, client, role: role ? `${role.system}:${role.role}` : '', sort, dir },
  };
}
