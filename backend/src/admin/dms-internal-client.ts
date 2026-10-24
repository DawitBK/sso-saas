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

import { IDP_CONFIG } from "../config.js";
import { createInternalApiClient } from "../infrastructure/internalApiClient.js";

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
  // A group (or a per-user "CN=user:<sub>" override) can assert more than
  // one DMS role at once now — DMS's own user_roles is many-to-many, and
  // idp_role_mappings used to cap this at one role per group, which meant an
  // account legitimately holding two DMS roles could only ever have one of
  // them reasserted by its next SSO login (see the migration this followed,
  // DMS's `20260923000002-idp-role-mappings-multi-role.sql`).
  roleNames: string[];
}

export interface DmsLiveStatus {
  exists: boolean;
  id: string | null;
  roles: string[];
  departmentIds: string[];
  pendingDepartmentIds: string[];
  active: boolean | null;
}

export interface DmsDepartment {
  id: string;
  code: string;
  name: string;
  orgUnitId: string;
  orgUnitCode: string;
  orgUnitName: string;
}

/** Thrown for both transport failures (DMS unreachable) and DMS-returned
 *  `{ error: { code, message } }` responses — callers branch on `.status`/`.code`
 *  the same way the rest of this router surfaces dmsError/officesError. */
export class DmsInternalApiError extends Error {
  status: number;
  code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = "DmsInternalApiError";
    this.status = status;
    this.code = code;
  }
}

// Shared factory (infrastructure/internalApiClient.ts) — see Finding 6/10 of the
// PHASE-02-10-14 code review. Timeout rationale (kept verbatim,
// still load-bearing): one caller of this module — resolveEdamsRolesForGroups,
// via auth/client-role-claims.ts — runs inside `findAccount`, which
// oidc-provider invokes on EVERY token issuance, refresh, and /userinfo call,
// for EVERY client. Without a timeout, a DMS internal API that accepts the
// connection and then hangs stalls that call for undici's default 300s header
// timeout — and because findAccount is shared, it stalls token issuance for
// GMS and the portal too, not just DMS. A DMS-side hang became a
// platform-wide login outage.
//
// Deliberately shorter than the GMS bridge's 8s: that one is a single hop in
// an interactive redirect chain, this one is on the critical path of every
// token the IdP mints. Callers already degrade gracefully on throw
// (client-role-claims.ts omits the claim and lets DMS fall back to its own
// role table), so failing fast is strictly better than blocking.
const client = createInternalApiClient({
  serviceLabel: "DMS",
  baseUrl: () => IDP_CONFIG.dms.apiBaseUrl,
  getApiKey: () => IDP_CONFIG.dmsInternalApiKey,
  timeoutMs: IDP_CONFIG.dms.internalTimeoutMs,
  notConfiguredMessage:
    "DMS_INTERNAL_API_KEY is not configured — set it in .env to manage DMS role permissions here.",
  createError: (message, status, code) =>
    new DmsInternalApiError(message, status, code),
});

function actorHeaders(actorEmail?: string): Record<string, string> {
  return actorEmail ? { "x-internal-actor": actorEmail } : {};
}

export async function listDmsRoles(
  tenantId: string,
  requestId?: string,
): Promise<DmsRole[]> {
  return client.request<DmsRole[]>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/roles`,
    undefined,
    requestId,
  );
}

export async function listDmsDepartments(
  tenantId: string,
  requestId?: string,
): Promise<DmsDepartment[]> {
  const result = await client.request<DmsDepartment[]>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/departments`,
    undefined,
    requestId,
  );
  return result;
}

export async function getDmsRolePermissions(
  tenantId: string,
  roleId: string,
  requestId?: string,
): Promise<DmsRolePermissions> {
  return client.request<DmsRolePermissions>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/roles/${encodeURIComponent(roleId)}/permissions`,
    undefined,
    requestId,
  );
}

export async function putDmsRolePermissions(
  tenantId: string,
  roleId: string,
  permissions: string[],
  actorEmail?: string,
  requestId?: string,
): Promise<DmsRolePermissions> {
  return client.request<DmsRolePermissions>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/roles/${encodeURIComponent(roleId)}/permissions`,
    {
      method: "PUT",
      headers: actorHeaders(actorEmail),
      body: JSON.stringify({ permissions }),
    },
    requestId,
  );
}

export async function getDmsUserOverrides(
  tenantId: string,
  userId: string,
  requestId?: string,
): Promise<DmsUserOverrides> {
  return client.request<DmsUserOverrides>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/permission-overrides`,
    undefined,
    requestId,
  );
}

/** Group DNs that carry one DMS role, for the Users list's role filter. */
export async function listDmsGroupsForRole(
  tenantId: string,
  roleName: string,
  requestId?: string,
): Promise<string[]> {
  const result = await client.request<{ roleName: string; groupDns: string[] }>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/by-role/${encodeURIComponent(roleName)}`,
    undefined,
    requestId,
  );
  return result.groupDns ?? [];
}

export async function listDmsMappedGroups(
  tenantId: string,
  requestId?: string,
): Promise<string[]> {
  const result = await client.request<{ groupDns: string[] }>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings`,
    undefined,
    requestId,
  );
  return result.groupDns;
}

/** Resolve AD group DNs to DMS coarse role names (SSO token claims). Called
 *  from findAccount (oidc-provider's account-resolution hook, invoked on
 *  every token issuance/refresh/userinfo call) via client-role-claims.ts,
 *  which has no per-request id available to it at that depth — requestId is
 *  correctly omitted there, not a gap in this fix. */
export async function resolveEdamsRolesForGroups(
  tenantId: string,
  groupDns: string[],
  requestId?: string,
): Promise<string[]> {
  const result = await client.request<{ roles: string[] }>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/resolve`,
    { method: "POST", body: JSON.stringify({ groupDns }) },
    requestId,
  );
  return result.roles ?? [];
}

export async function getDmsRoleMapping(
  tenantId: string,
  groupDn: string,
  requestId?: string,
): Promise<DmsRoleMapping> {
  return client.request<DmsRoleMapping>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/${encodeURIComponent(groupDn)}`,
    undefined,
    requestId,
  );
}

/** Full replace: this group asserts exactly `roleNames` afterward, same
 *  semantics as putDmsRolePermissions above. Pass `[]` to unmap the group
 *  entirely (equivalent to the old `roleName: null`). */
export async function putDmsRoleMapping(
  tenantId: string,
  groupDn: string,
  roleNames: string[],
  actorEmail?: string,
  requestId?: string,
): Promise<DmsRoleMapping> {
  return client.request<DmsRoleMapping>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/role-mappings/${encodeURIComponent(groupDn)}`,
    {
      method: "PUT",
      headers: actorHeaders(actorEmail),
      body: JSON.stringify({ roleNames }),
    },
    requestId,
  );
}

export async function getDmsUserStatusByEmail(
  tenantId: string,
  email: string,
  requestId?: string,
): Promise<DmsLiveStatus> {
  return client.request<DmsLiveStatus>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/by-email/${encodeURIComponent(email)}/status`,
    undefined,
    requestId,
  );
}

export async function putDmsUserDepartments(
  tenantId: string,
  email: string,
  departmentIds: string[],
  actorEmail?: string,
  requestId?: string,
): Promise<{
  email: string;
  userId?: string;
  departmentIds: string[];
  pending: boolean;
}> {
  return client.request(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/by-email/${encodeURIComponent(email)}/departments`,
    {
      method: "PUT",
      headers: actorHeaders(actorEmail),
      body: JSON.stringify({ departmentIds }),
    },
    requestId,
  );
}

export async function putDmsUserOverrides(
  tenantId: string,
  userId: string,
  grants: string[],
  revokes: string[],
  actorEmail?: string,
  requestId?: string,
): Promise<DmsUserOverrides> {
  return client.request<DmsUserOverrides>(
    `/internal/roles/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/permission-overrides`,
    {
      method: "PUT",
      headers: actorHeaders(actorEmail),
      body: JSON.stringify({ grants, revokes }),
    },
    requestId,
  );
}
