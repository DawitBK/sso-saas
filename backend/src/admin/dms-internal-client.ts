/**
 * HTTP client for DMS's internal admin API (`/api/v1/internal/roles/...`),
 * mounted on DMS at `DMS_API_BASE_URL` (default `http://localhost:7100/api/v1`).
 * The admin console MUST go through this for writes to DMS's role-permission
 * table (`role_permissions`) and per-user permission overrides
 * (`user_permission_overrides`) — never via direct SQL from SSO like the
 * DMS-role-name mapping writes elsewhere in this codebase (`idp_role_mappings`),
 * because DMS's service layer behind this API does privilege-escalation
 * checks, audit logging, and session revocation on every write that a direct
 * SQL write would silently bypass.
 *
 * Auth: shared secret via `x-internal-api-key` (must equal DMS's own
 * `DMS_INTERNAL_API_KEY`), optional `x-internal-actor` for DMS-side audit
 * attribution of the admin who initiated the change.
 */

import { IDP_CONFIG } from '../config.js';

export interface DmsRole {
  id: string;
  name: string;
  description: string | null;
}

export interface DmsRolePermissions {
  roleId: string;
  roleName: string;
  permissions: string[];
}

export interface DmsUserOverrides {
  grants: string[];
  revokes: string[];
}

export interface DmsRoleMapping {
  groupDn: string;
  roleName: string | null;
}

export interface DmsLiveStatus {
  exists: boolean;
  id: string | null;
  roles: string[];
  active: boolean | null;
}

/** Thrown for both transport failures (DMS unreachable) and DMS-returned
 *  `{ error: { code, message } }` responses — callers branch on `.status`/`.code`
 *  the same way the rest of this router surfaces dmsError/officesError. */
export class DmsInternalApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = 'DmsInternalApiError';
    this.status = status;
    this.code = code;
  }
}

function baseUrl(): string {
  return IDP_CONFIG.dms.apiBaseUrl.replace(/\/+$/, '');
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  if (!IDP_CONFIG.dmsInternalApiKey) {
    throw new DmsInternalApiError(
      'DMS_INTERNAL_API_KEY is not configured — set it in .env to manage DMS role permissions here.',
      503,
      'ERR-INTERNAL-API-DISABLED',
    );
  }

  const url = `${baseUrl()}${path}`;
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers: {
        'content-type': 'application/json',
        'x-internal-api-key': IDP_CONFIG.dmsInternalApiKey,
        ...(init?.headers as Record<string, string> | undefined),
      },
    });
  } catch (err) {
    throw new DmsInternalApiError(`Could not reach DMS at ${url}: ${(err as Error).message}`, 503, 'ERR-DMS-UNREACHABLE');
  }

  const body = (await res.json().catch(() => null)) as { data?: T; error?: { code?: string; message?: string } } | null;

  if (!res.ok) {
    const message = body?.error?.message ?? `DMS internal API request failed with status ${res.status}`;
    const code = body?.error?.code ?? 'ERR-UNKNOWN';
    throw new DmsInternalApiError(message, res.status, code);
  }

  return (body?.data ?? (body as unknown)) as T;
}

function actorHeaders(actorEmail?: string): Record<string, string> {
  return actorEmail ? { 'x-internal-actor': actorEmail } : {};
}

export async function listDmsRoles(tenantId: string): Promise<DmsRole[]> {
  return request<DmsRole[]>(`/internal/roles/tenants/${encodeURIComponent(tenantId)}/roles`);
}

export async function getDmsRolePermissions(tenantId: string, roleId: string): Promise<DmsRolePermissions> {
  return request<DmsRolePermissions>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/roles/${encodeURIComponent(roleId)}/permissions`,
  );
}

export async function putDmsRolePermissions(
  tenantId: string,
  roleId: string,
  permissions: string[],
  actorEmail?: string,
): Promise<DmsRolePermissions> {
  return request<DmsRolePermissions>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/roles/${encodeURIComponent(roleId)}/permissions`,
    { method: 'PUT', headers: actorHeaders(actorEmail), body: JSON.stringify({ permissions }) },
  );
}

export async function getDmsUserOverrides(tenantId: string, userId: string): Promise<DmsUserOverrides> {
  return request<DmsUserOverrides>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/permission-overrides`,
  );
}

export async function listDmsMappedGroups(tenantId: string): Promise<string[]> {
  const result = await request<{ groupDns: string[] }>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings`,
  );
  return result.groupDns;
}

/** Resolve AD group DNs to DMS coarse role names (SSO token claims). */
export async function resolveEdamsRolesForGroups(
  tenantId: string,
  groupDns: string[],
): Promise<string[]> {
  const result = await request<{ roles: string[] }>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/resolve`,
    { method: 'POST', body: JSON.stringify({ groupDns }) },
  );
  return result.roles ?? [];
}

export async function getDmsRoleMapping(tenantId: string, groupDn: string): Promise<DmsRoleMapping> {
  return request<DmsRoleMapping>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/${encodeURIComponent(groupDn)}`,
  );
}

export async function putDmsRoleMapping(
  tenantId: string,
  groupDn: string,
  roleName: string | null,
  actorEmail?: string,
): Promise<DmsRoleMapping> {
  return request<DmsRoleMapping>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/${encodeURIComponent(groupDn)}`,
    { method: 'PUT', headers: actorHeaders(actorEmail), body: JSON.stringify({ roleName }) },
  );
}

export async function getDmsUserStatusByEmail(tenantId: string, email: string): Promise<DmsLiveStatus> {
  return request<DmsLiveStatus>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/by-email/${encodeURIComponent(email)}/status`,
  );
}

export async function putDmsUserOverrides(
  tenantId: string,
  userId: string,
  grants: string[],
  revokes: string[],
  actorEmail?: string,
): Promise<DmsUserOverrides> {
  return request<DmsUserOverrides>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/permission-overrides`,
    { method: 'PUT', headers: actorHeaders(actorEmail), body: JSON.stringify({ grants, revokes }) },
  );
}
