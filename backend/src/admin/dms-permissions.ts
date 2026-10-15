/**
 * Mirror of DMS's own `DMS/backend/src/config/permissions.ts` — copied
 * verbatim as plain data (no cross-repo import: these are two independently
 * deployable services, and this repo has no build-time visibility into DMS's
 * source tree). This is reference data ONLY, for labeling/grouping/defaulting
 * checkboxes in the admin UI — DMS's own file remains the authoritative
 * definition of what each permission/role actually means or resolves to at
 * runtime. If DMS adds/renames a permission or role, this file needs a manual
 * re-sync; nothing here enforces that automatically.
 *
 * Only the permission NAMES are mirrored. DMS's role-to-permission table was
 * mirrored here too and was read by nothing — a second, silently drifting copy
 * of another service's authorization model living inside the identity provider.
 * It was deleted on 2026-09-06. If you need a role's permissions, ask DMS.
 */

export const PERMISSIONS = {
  DOCUMENT_READ: 'document:read',
  DOCUMENT_READ_ALL: 'document:read_all',
  DOCUMENT_UPLOAD: 'document:upload',
  DOCUMENT_ARCHIVE: 'document:archive',
  DOCUMENT_PURGE: 'document:purge',
  DOCUMENT_CHECKOUT: 'document:checkout',
  VERSION_MANAGE: 'version:manage',
  FOLDER_CREATE: 'folder:create',
  FOLDER_READ: 'folder:read',
  FOLDER_DELETE: 'folder:delete',
  USER_MANAGE: 'user:manage',
  ROLE_READ: 'role:read',
  ROLE_MANAGE: 'role:manage',
  DEPT_READ: 'department:read',
  DEPT_MANAGE: 'department:manage',
  DOCTYPE_READ: 'doctype:read',
  DOCTYPE_MANAGE: 'doctype:manage',
  AUDIT_READ: 'audit:read',
  WORKFLOW_READ: 'workflow:read',
  WORKFLOW_MANAGE: 'workflow:manage',
  WORKFLOW_APPROVE: 'workflow:approve',
  RETENTION_READ: 'retention:read',
  RETENTION_MANAGE: 'retention:manage',
  LEGAL_HOLD_READ: 'legalhold:read',
  LEGAL_HOLD_MANAGE: 'legalhold:manage',
  SEARCH_READ: 'search:read',
  SEARCH_SCOPE_ALL: 'search:scope_all',
  NOTIFICATION_READ: 'notification:read',
  SIGNING_READ: 'signing:read',
  SIGNING_MANAGE: 'signing:manage',
  OPERATIONS_READ: 'operations:read',
  OPERATIONS_MANAGE: 'operations:manage',
  ACL_MANAGE: 'acl:manage',
  ACL_BYPASS_ADMIN: 'acl:bypass_admin',
  TENANT_READ: 'tenant:read',
  TENANT_MANAGE: 'tenant:manage',
  // CAMS — correspondence
  LETTER_READ: 'letter:read',
  LETTER_READ_ALL: 'letter:read_all',
  LETTER_CREATE: 'letter:create',
  LETTER_REVIEW: 'letter:review',
  LETTER_APPROVE: 'letter:approve',
  LETTER_DISPATCH: 'letter:dispatch',
  LETTER_REGISTER: 'letter:register',
  ORG_UNIT_READ: 'orgunit:read',
  ORG_UNIT_MANAGE: 'orgunit:manage',
  // Unified approval engine
  APPROVAL_SUBMIT: 'approval:submit',
  APPROVAL_DECIDE: 'approval:decide',
  APPROVAL_ADMIN: 'approval:admin',
  AUDIT_STAGE_DECIDE: 'audit-stage:decide',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const ALL_PERMISSIONS: string[] = Object.values(PERMISSIONS);

/** `document:read_all` → `Read all`. Simple title-casing, not a hand-tuned
 *  label per permission — good enough for a checkbox list of ~40 entries. */
export function permissionLabel(permission: string): string {
  const action = permission.includes(':') ? permission.slice(permission.indexOf(':') + 1) : permission;
  return action
    .split(/[_-]/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

/** `document:read_all` → `document`. Groups the checkbox grid so it isn't one
 *  flat list of ~40 boxes. */
export function permissionGroup(permission: string): string {
  return permission.includes(':') ? permission.slice(0, permission.indexOf(':')) : permission;
}

export interface PermissionOption { value: string; label: string }
export interface PermissionGroup { group: string; permissions: PermissionOption[] }

/** All known DMS permissions, grouped by their `group:` prefix and sorted for
 *  stable, predictable rendering order. */
export function groupedPermissions(): PermissionGroup[] {
  const byGroup = new Map<string, PermissionOption[]>();
  for (const permission of ALL_PERMISSIONS) {
    const group = permissionGroup(permission);
    if (!byGroup.has(group)) byGroup.set(group, []);
    byGroup.get(group)!.push({ value: permission, label: permissionLabel(permission) });
  }
  return [...byGroup.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([group, permissions]) => ({ group, permissions }));
}
