/**
 * Access management: what a person or a group is allowed to open, and the live lookups that tell an administrator whether
 * DMS and GMS agree. Shared by the console's JSON API (api/v1/admin.router.ts, clients.router.ts) and by the seed scripts.
 *
 * This file used to be `admin/router.ts` and also held the first, server-rendered admin console (`/admin` on the backend's own port).
 * That console was retired 2026-10-11: the Next.js console calls /api/v1/admin/* for everything, so the routes below the
 * helpers had no caller. What stayed is the part other code imports.
 */

import type { Request } from "express";
import { PlatformAdminOnlyError, isPlatformAdminEmail } from "../auth/platform-admin.js";
import { reportNonOwnerPrivilegeAttempt } from "../ops/privilegeWatch.js";
import { IDP_CONFIG } from "../config.js";
import { logger } from "../logging/logger.js";
import { pool } from "../db/pool.js";
import { revokeAllSessions } from "../auth/revoke.js";
import { writeAudit } from "./audit.js";
import {
  listDmsRoleNames,
  listGmsOfficeScopedRoleNames,
  listGmsRoleNames,
  DMS_ROLES_FALLBACK,
} from "./client-roles.js";
import {
  listDmsRoles,
  getDmsRolePermissions,
  getDmsUserOverrides,
  listDmsMappedGroups,
  getDmsRoleMapping,
  putDmsRoleMapping,
  getDmsUserStatusByEmail,
  listDmsDepartments,
  putDmsUserDepartments,
  DmsInternalApiError,
  type DmsRole,
  type DmsDepartment,
} from "./dms-internal-client.js";
import {
  GmsInternalApiError,
  getGmsUserStatus,
  listGmsOffices,
} from "./gms-internal-client.js";
import { APP_REGISTRY } from "../portal/catalog.js";

const DMS_RP = "edams";
// EXECUTIVE included so the standing correspondence-oversight demo role (DMS's
// ROLE_PERMISSIONS.EXECUTIVE, e.g. chief@edams.local in DMS's own demo-user
// seed) is actually selectable/editable here — this list previously omitted
// it even though DMS itself already treats EXECUTIVE as a first-class role.
/** @deprecated Prefer listDmsRoleNames() — kept for callers that need a sync fallback. */
export const DMS_ROLES = [...DMS_ROLES_FALLBACK];

export async function roleCatalog(): Promise<{
  dmsRoles: string[];
  gmsRoles: string[];
  gmsOfficeScopedRoles: string[];
}> {
  const [dmsRoles, gmsRoles, gmsOfficeScopedRoles] = await Promise.all([
    listDmsRoleNames(),
    listGmsRoleNames(),
    listGmsOfficeScopedRoleNames(),
  ]);
  return { dmsRoles, gmsRoles, gmsOfficeScopedRoles };
}

/** The apps a group can be entitled to. Derived from portal/catalog.ts's APP_REGISTRY, the
 *  single list of launcher systems, so a new system cannot be tiled but not entitle-able. */
export const APPS = APP_REGISTRY.map(({ rp, label }) => ({ rp, label }));

export interface Office {
  id: number;
  name: string;
}

export async function listOffices(
  requestId?: string,
): Promise<{ offices: Office[]; error: string | null }> {
  if (!IDP_CONFIG.gms.internalApiKey) {
    return {
      offices: [],
      error:
        "GMS_INTERNAL_API_KEY is not configured — offices cannot be listed.",
    };
  }
  try {
    return { offices: await listGmsOffices(requestId), error: null };
  } catch (err) {
    const message =
      err instanceof GmsInternalApiError
        ? err.message
        : "Could not reach the GMS internal API to list offices.";
    return { offices: [], error: message };
  }
}

export async function listDmsDepartmentsForAdmin(
  requestId?: string,
): Promise<{ departments: DmsDepartment[]; error: string | null }> {
  if (!IDP_CONFIG.dmsInternalApiKey) {
    return {
      departments: [],
      error:
        "DMS_INTERNAL_API_KEY is not configured — departments cannot be listed.",
    };
  }
  try {
    return {
      departments: await listDmsDepartments(
        IDP_CONFIG.dmsDefaultTenant,
        requestId,
      ),
      error: null,
    };
  } catch (err) {
    const message =
      err instanceof DmsInternalApiError
        ? err.message
        : "Could not reach the DMS internal API to list departments.";
    return { departments: [], error: message };
  }
}

export async function setDmsDepartmentsForUser(
  email: string,
  departmentIds: string[],
  actorEmail: string,
  requestId?: string,
): Promise<void> {
  if (!IDP_CONFIG.dmsInternalApiKey) {
    throw new DmsInternalApiError(
      "DMS_INTERNAL_API_KEY is not configured — set it to manage DMS departments here.",
      503,
      "ERR-DMS-NOT-CONFIGURED",
    );
  }
  await putDmsUserDepartments(
    IDP_CONFIG.dmsDefaultTenant,
    email,
    departmentIds,
    actorEmail,
    requestId,
  );
}

/**
 * Every locally-created user gets one dedicated, auto-managed group — this is
 * what lets the admin UI assign "this user gets role X in DMS, role Y in GMS"
 * directly on the user's own page, with no group DN ever exposed or typed.
 * Shared/AD groups (for assigning many users at once) still work independently
 * via the Groups page and idp_user_groups.
 */
export function personalGroupDn(userId: string): string {
  return `CN=user:${userId},OU=Users,DC=examplecorp,DC=com`;
}

/** Personal groups are auto-managed via System access (above) — never a valid
 *  target for the free-form "add to group" field. */
export function isPersonalGroupDn(dn: string): boolean {
  return dn.startsWith("CN=user:");
}

export interface AccessState {
  // A group (or per-user override) can assert more than one DMS role at
  // once — DMS's own user_roles is many-to-many, and idp_role_mappings used
  // to cap this at one role per group, which meant an account legitimately
  // holding two DMS roles could only ever have one of them reasserted by its
  // next SSO login. See DMS/backend/migrations/20260923000002-idp-role-
  // mappings-multi-role.sql.
  dmsRoles: string[];
  dmsError: string | null;
  gmsRole: string | null;
  officeId: number | null;
}

/**
 * email is optional: office assignment is per-user (idp_gms_user_office is keyed
 * by email), so it's only meaningful when called for a specific user. Group-detail
 * calls this without an email and just gets officeId: null back.
 */
export async function getAccess(
  dn: string,
  email?: string,
  requestId?: string,
): Promise<AccessState> {
  let dmsRoles: string[] = [];
  let dmsError: string | null = null;
  if (IDP_CONFIG.dmsInternalApiKey) {
    try {
      dmsRoles = (
        await getDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, requestId)
      ).roleNames;
    } catch (err) {
      dmsError =
        err instanceof DmsInternalApiError
          ? err.message
          : "Could not reach the DMS internal API.";
    }
  } else {
    dmsError =
      "DMS_INTERNAL_API_KEY is not configured — set it in .env to manage DMS roles here.";
  }
  const [{ rows: gmsRows }, { rows: officeRows }] = await Promise.all([
    pool.query<{ role_name: string }>(
      "SELECT role_name FROM idp_gms_role_mappings WHERE group_dn = $1",
      [dn],
    ),
    email
      ? pool.query<{ office_id: number }>(
          "SELECT office_id FROM idp_gms_user_office WHERE email = $1",
          [email.toLowerCase()],
        )
      : Promise.resolve({ rows: [] as { office_id: number }[] }),
  ]);
  return {
    dmsRoles,
    dmsError,
    gmsRole: gmsRows[0]?.role_name ?? null,
    officeId: officeRows[0]?.office_id ?? null,
  };
}

/**
 * Live, authoritative status of the user INSIDE each app — read straight from the
 * app's own database. SSO's assignment is applied at EVERY sign-in, not only the first:
 * for DMS, SSO's list wins unless a DMS administrator edited the roles inside DMS and
 * SSO's list is unchanged since (rules R1-R4 in DMS/Documentations/SSO-DMS-SYNC-AND-
 * CONFLICT-RULES.md); saving access signs the person out when something changed.
 */
// `id` is the app's OWN primary key for this user (DMS's UUID / GMS's bigint,
// stringified) — needed so callers can address DMS's internal permissions API
// by DMS user id without a second lookup query.
export interface LiveAppStatus {
  exists: boolean;
  id: string | null;
  roles: string[];
  departmentIds: string[];
  pendingDepartmentIds: string[];
  officeId: number | null;
  active: boolean | null;
  error: string | null;
}

export async function liveDmsStatus(
  email: string,
  requestId?: string,
): Promise<LiveAppStatus> {
  const none: LiveAppStatus = {
    exists: false,
    id: null,
    roles: [],
    departmentIds: [],
    pendingDepartmentIds: [],
    officeId: null,
    active: null,
    error: null,
  };
  if (!IDP_CONFIG.dmsInternalApiKey)
    return { ...none, error: "DMS_INTERNAL_API_KEY is not configured." };
  try {
    const status = await getDmsUserStatusByEmail(
      IDP_CONFIG.dmsDefaultTenant,
      email,
      requestId,
    );
    if (!status.exists)
      return { ...none, pendingDepartmentIds: status.pendingDepartmentIds };
    return {
      exists: true,
      id: status.id,
      roles: status.roles,
      departmentIds: status.departmentIds,
      pendingDepartmentIds: status.pendingDepartmentIds,
      officeId: null,
      active: status.active,
      error: null,
    };
  } catch (err) {
    const message =
      err instanceof DmsInternalApiError
        ? err.message
        : "Could not reach the DMS internal API.";
    return { ...none, error: message };
  }
}

export async function liveGmsStatus(
  email: string,
  requestId?: string,
): Promise<LiveAppStatus> {
  const none: LiveAppStatus = {
    exists: false,
    id: null,
    roles: [],
    departmentIds: [],
    pendingDepartmentIds: [],
    officeId: null,
    active: null,
    error: null,
  };
  if (!IDP_CONFIG.gms.internalApiKey)
    return { ...none, error: "GMS_INTERNAL_API_KEY is not configured." };
  try {
    const status = await getGmsUserStatus(email, requestId);
    if (!status.exists) return none;
    return {
      exists: true,
      id: status.id,
      roles: status.roles,
      departmentIds: [],
      pendingDepartmentIds: [],
      officeId: status.officeId,
      active: status.active,
      error: null,
    };
  } catch (err) {
    const message =
      err instanceof GmsInternalApiError
        ? err.message
        : "Could not reach the GMS internal API.";
    return { ...none, error: message };
  }
}

export interface DmsPermissionsState {
  roleId: string;
  roleDefaults: string[];
  grants: string[];
  revokes: string[];
  effective: Set<string>;
}

/**
 * Resolves the DMS permission-checkbox state for a user: the UNION of every
 * held role's defaults ∪ GRANT overrides − REVOKE overrides. Only meaningful
 * when the user has at least one DMS role assigned AND already has a DMS
 * user row (dmsUserId, from liveDmsStatus) — before that first DMS sign-in
 * there's no DMS user id for the internal API's user-scoped endpoints to
 * address. `roleDefaults`/`roleId` describe the FIRST role in the array only
 * (kept for callers that render "the role" as one label); `effective` is the
 * true union across all of them, which is what actually matters for what the
 * user can do.
 */
export async function resolveDmsPermissions(
  dmsRoles: string[],
  dmsUserId: string,
  requestId?: string,
): Promise<DmsPermissionsState> {
  const roles = await listDmsRoles(IDP_CONFIG.dmsDefaultTenant, requestId);
  const matched = dmsRoles
    .map((name) => roles.find((r) => r.name === name))
    .filter((r): r is DmsRole => Boolean(r));
  if (dmsRoles.length === 0 || matched.length === 0) {
    throw new DmsInternalApiError(
      `None of the DMS role(s) "${dmsRoles.join(", ")}" were found in DMS (tenant "${IDP_CONFIG.dmsDefaultTenant}").`,
      404,
      "ERR-ROLE-NOT-FOUND",
    );
  }
  const [rolePermsList, overrides] = await Promise.all([
    Promise.all(
      matched.map((role) =>
        getDmsRolePermissions(IDP_CONFIG.dmsDefaultTenant, role.id, requestId),
      ),
    ),
    getDmsUserOverrides(IDP_CONFIG.dmsDefaultTenant, dmsUserId, requestId),
  ]);
  const roleDefaults = [
    ...new Set(rolePermsList.flatMap((rp) => rp.permissions)),
  ];
  const effective = new Set(roleDefaults);
  for (const p of overrides.grants) effective.add(p);
  for (const p of overrides.revokes) effective.delete(p);
  return {
    roleId: matched[0].id,
    roleDefaults,
    grants: overrides.grants,
    revokes: overrides.revokes,
    effective,
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Minimal local retry-with-backoff — there is no shared retry/backoff utility
 * elsewhere in this codebase (checked), and applyAccess below is presently the
 * only caller that needs one, so this stays local rather than pulling in a
 * dependency for one call site. Returns whether `fn` eventually succeeded;
 * never throws itself (callers decide how to react to exhaustion).
 */
async function withRetries(
  fn: () => Promise<void>,
  attempts: number,
  baseDelayMs: number,
): Promise<boolean> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await fn();
      return true;
    } catch {
      if (attempt < attempts) await sleep(baseDelayMs * attempt);
    }
  }
  return false;
}

/**
 * Refuse a whole-form access save while DMS cannot be read. The form is filled from a DMS read; if that read failed the
 * checkboxes are empty, and saving them would replace the person's real DMS roles with none. Throws a DmsInternalApiError
 * the caller turns into a 409/503 instead of applying anything.
 */
export async function assertDmsReadableForAccessSave(dn: string, requestId?: string): Promise<void> {
  if (!IDP_CONFIG.dmsInternalApiKey) return;
  try {
    await getDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, requestId);
  } catch (err) {
    throw new DmsInternalApiError(
      `DMS could not be read, so the roles shown on this form may not be the person's real ones. Nothing was changed - reload once DMS is reachable. (${(err as Error).message})`,
      503,
      'ERR-DMS-UNREADABLE',
    );
  }
}

/** Apply (or clear) a user's DMS/GMS role + GMS office in one shot: ensures group
 *  membership, the app entitlement (any role ⇒ entitled), and the app's own role
 *  mapping. officeId is required by GMS for office-scoped roles (validated by caller).
 *  actorEmail/req are the admin making the change — needed here (not just by the
 *  caller's own writeAudit call) so a detected IdP/DMS desync can be logged with an
 *  actor + IP/UA even though it's discovered mid-function, before the caller's normal
 *  audit write runs. */
export async function applyAccess(
  userId: string,
  email: string,
  dn: string,
  dmsRoles: string[],
  gmsRole: string,
  officeId: number | null,
  actorEmail: string,
  req: Request,
  requestId?: string,
): Promise<void> {
  // FIX: unlike addUserToGroup/removeUserFromGroup (which revoke on every call
  // since each represents one deliberate add/remove), this function is called
  // by a "save the whole access form" endpoint that always submits the FULL
  // current state — including an admin just reviewing and re-saving with no
  // edits. So revocation here must be conditional on something actually
  // changing, not unconditional, or every no-op save would force the user to
  // re-login everywhere. Snapshot current state before any mutation below; if
  // a read fails, treat it as "changed" — under-revoking is the real security
  // gap this closes, a needless revoke on a read hiccup is just an
  // inconvenience.
  const sortedEq = (a: string[], b: string[]) =>
    a.length === b.length &&
    [...a].sort().every((v, i) => v === [...b].sort()[i]);
  let accessChanged = false;
  let previousDmsRoles: string[] | null = null; // DMS's mapping before this call, so a later failure can put it back
  // Roles were asked for but DMS cannot be reached at all: refuse. Returning success here used to drop the DMS roles silently.
  if (dmsRoles.length > 0 && !IDP_CONFIG.dmsInternalApiKey) {
    throw new Error('DMS_INTERNAL_API_KEY is not set, so DMS roles cannot be applied - nothing was changed.');
  }
  if (IDP_CONFIG.dmsInternalApiKey) {
    const currentDmsRoles = await getDmsRoleMapping(
      IDP_CONFIG.dmsDefaultTenant,
      dn,
      requestId,
    )
      .then((m) => m.roleNames)
      .catch(() => null);
    previousDmsRoles = currentDmsRoles;
    if (currentDmsRoles === null || !sortedEq(currentDmsRoles, dmsRoles))
      accessChanged = true;
  }
  {
    const { rows } = await pool.query<{ role_name: string }>(
      "SELECT role_name FROM idp_gms_role_mappings WHERE group_dn = $1",
      [dn],
    );
    if ((rows[0]?.role_name ?? "") !== (gmsRole || "")) accessChanged = true;
  }
  {
    const { rows } = await pool.query<{ office_id: number }>(
      "SELECT office_id FROM idp_gms_user_office WHERE email = $1",
      [email.toLowerCase()],
    );
    if ((rows[0]?.office_id ?? null) !== officeId) accessChanged = true;
  }

  await pool.query(
    "INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    [userId, dn],
  );

  if (dmsRoles.length > 0 && IDP_CONFIG.dmsInternalApiKey) {
    // Remember whether the entitlement already existed: the compensation below must
    // only undo what THIS call added. Deleting a pre-existing entitlement because a
    // re-save hit a DMS blip would turn a transient failure into lost access (SSO
    // says "not entitled" while DMS still holds the old role mapping).
    const { rowCount: entitlementRows } = await pool.query(
      "SELECT 1 FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2",
      [DMS_RP, dn],
    );
    const hadEntitlement = (entitlementRows ?? 0) > 0;
    await pool.query(
      "INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [DMS_RP, dn],
    );
    try {
      await putDmsRoleMapping(
        IDP_CONFIG.dmsDefaultTenant,
        dn,
        dmsRoles,
        actorEmail,
        requestId,
      );
    } catch (err) {
      // A timeout does not mean "not applied": DMS may have committed just before the abort. Read it back; if the
      // mapping already is what was asked for, the write succeeded and undoing the entitlement would be the desync.
      if (err instanceof DmsInternalApiError && err.code === 'ERR-DMS-TIMEOUT') {
        const nowRoles = await getDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, requestId).then((m) => m.roleNames).catch(() => null);
        if (nowRoles && sortedEq(nowRoles, dmsRoles)) {
          logger.warn({ dn }, '[idp:admin] DMS role write timed out but had been applied; continuing');
          err = null as never;
        }
      }
      if (err) {
      // Two different databases can't share one transaction — compensate by
      // undoing the IdP-side entitlement rather than leaving "entitled to DMS"
      // with no DMS-side role mapping behind it (silently desynced forever).
      // The compensating delete gets its own retries: a bare single attempt
      // would let a transient blip on THIS query, at exactly the wrong moment,
      // turn a recoverable failure into a permanent silent desync.
      // Nothing to undo when the entitlement was already there before this call.
      const compensated = hadEntitlement
        ? true
        : await withRetries(
            async () => {
              await pool.query(
                "DELETE FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2",
                [DMS_RP, dn],
              );
            },
            3,
            250,
          );
      if (!compensated) {
        // All compensating-delete retries exhausted: IdP still believes this
        // group is entitled to DMS, the DMS-side role mapping write failed, and
        // we could not undo the IdP-side entitlement either. This is now a
        // confirmed, real desync between IdP and DMS state — it must never
        // vanish into a swallowed catch. Log it as its own audit action,
        // distinct from a normal access change, so it's discoverable via
        // /admin/audit even though it can't be auto-healed from here.
        await writeAudit(req, actorEmail, "entitlement.desync", dn, {
          relyingParty: DMS_RP,
          dmsRoles,
          userId,
          detail:
            "IdP believes this group is entitled to DMS; the DMS-side role mapping write failed and the " +
            "compensating removal of the IdP-side entitlement failed after 3 attempts. DMS-side state is " +
            "unknown — reconcile idp_app_entitlements against DMS idp_role_mappings for this group manually.",
          dmsWriteError: (err as Error).message,
        }).catch((auditErr) => {
          logger.error(
            { err: auditErr },
            "[idp:admin] failed to write entitlement.desync audit row",
          );
        });
      }
      const failure = `DMS role mapping failed — access change was not applied: ${(err as Error).message}`;
      // Keep the DMS error's status and code (ERR-DMS-UNREACHABLE / -TIMEOUT / 422s) so
      // the admin API can answer 503/422 with a code instead of an opaque 500.
      throw err instanceof DmsInternalApiError
        ? new DmsInternalApiError(failure, err.status, err.code)
        : new Error(failure);
      }
    }
  } else if (IDP_CONFIG.dmsInternalApiKey) {
    // DMS first, entitlement second: if DMS cannot be reached the call fails with
    // BOTH sides still as they were. (The old order deleted the entitlement and then
    // threw, leaving the DMS-side mapping live behind an entitlement SSO had removed.)
    await putDmsRoleMapping(
      IDP_CONFIG.dmsDefaultTenant,
      dn,
      [],
      actorEmail,
      requestId,
    );
    await pool.query(
      "DELETE FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2",
      [DMS_RP, dn],
    );
  }

  // The GMS-side writes below are all against the IdP's own pool (unlike the DMS
  // writes above, which are unavoidably cross-database) — so unlike those, these
  // CAN and SHOULD be made truly atomic with each other via a real transaction on
  // one held connection, rather than several independent pool.query calls that
  // could each land on a different pooled client and partially apply.
  const normalizedEmail = email.toLowerCase();
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (gmsRole) {
      await client.query(
        "INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        ["gms", dn],
      );
      await client.query(
        "DELETE FROM idp_gms_role_mappings WHERE group_dn = $1",
        [dn],
      );
      await client.query(
        "INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2)",
        [dn, gmsRole],
      );
      if (officeId) {
        await client.query(
          `INSERT INTO idp_gms_user_office (email, office_id) VALUES ($1, $2)
           ON CONFLICT (email) DO UPDATE SET office_id = EXCLUDED.office_id`,
          [normalizedEmail, officeId],
        );
      } else {
        await client.query("DELETE FROM idp_gms_user_office WHERE email = $1", [
          normalizedEmail,
        ]);
      }
    } else {
      await client.query(
        "DELETE FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2",
        ["gms", dn],
      );
      await client.query(
        "DELETE FROM idp_gms_role_mappings WHERE group_dn = $1",
        [dn],
      );
      await client.query("DELETE FROM idp_gms_user_office WHERE email = $1", [
        normalizedEmail,
      ]);
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    // The DMS side was already written and cannot join this transaction: put it back, or a demotion stays applied in DMS
    // while SSO (and the user's live session) still hold the old state. If even that fails, the sync is unknown: revoke
    // the user's sessions and leave a desync row for the administrators.
    if (previousDmsRoles && IDP_CONFIG.dmsInternalApiKey && !sortedEq(previousDmsRoles, dmsRoles)) {
      const restored = await withRetries(async () => { await putDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, previousDmsRoles!, actorEmail, requestId); }, 3, 250);
      if (!restored) {
        await writeAudit(req, actorEmail, 'entitlement.desync', dn, { relyingParty: DMS_RP, userId, detail: 'The GMS write failed after the DMS mapping was changed and putting the DMS mapping back also failed; DMS holds the NEW roles while SSO holds the old state.' }).catch(() => {});
        await revokeAllSessions(userId, email).catch(() => {});
      }
    }
    throw err;
  } finally {
    client.release();
  }

  // Same reasoning as addUserToGroup/removeUserFromGroup: this can grant or
  // change an app role, so a real change must invalidate existing sessions —
  // conditioned on accessChanged (computed above) so a no-op re-save doesn't.
  if (accessChanged) {
    await revokeAllSessions(userId, email);
  }
}

/**
 * Add a user to a group (any group, including the admin group), auditing and
 * revoking sessions the same way regardless of caller: the free-text "add to
 * group" form (POST /users/:id/groups) and the "IdP Administrator" checkbox
 * on the Access form (POST /users/:id/access) both need identical behavior
 * here — a distinct audit action for the admin group so granting it is
 * impossible to miss scanning /admin/audit, and an immediate session revoke
 * since group membership can grant admin console access or an app role.
 */
export async function addUserToGroup(
  userId: string,
  email: string,
  groupDn: string,
  actorEmail: string,
  req: Request,
): Promise<void> {
  const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
  // Who is an IdP administrator is decided by the platform administrator alone.
  if (grantsAdmin && !(await isPlatformAdminEmail(actorEmail))) {
    reportNonOwnerPrivilegeAttempt({ email: actorEmail, ip: req.ip }, "admin_group.add", { targetUserId: userId });
    throw new PlatformAdminOnlyError();
  }
  // Same reasoning as applyAccess's GMS block below: the group-membership
  // write and its audit row are both against this same IdP database, so
  // unlike a cross-DB write there is no reason to leave them as two
  // independent, non-atomic operations — a crash between them used to leave
  // a group change with no audit row, or vice versa (P2-5).
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING",
      [userId, groupDn],
    );
    await writeAudit(
      req,
      actorEmail,
      grantsAdmin ? "user.admin_group.add" : "user.group.add",
      email,
      { userId, groupDn, grantsAdmin },
      client,
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  await revokeAllSessions(userId, email);
}

/** Remove a user from a group — mirrors addUserToGroup above, same distinct
 *  admin-group audit action name and session revoke on the way out. */
export async function removeUserFromGroup(
  userId: string,
  email: string,
  groupDn: string,
  actorEmail: string,
  req: Request,
): Promise<void> {
  const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
  if (grantsAdmin && !(await isPlatformAdminEmail(actorEmail))) {
    reportNonOwnerPrivilegeAttempt({ email: actorEmail, ip: req.ip }, "admin_group.remove", { targetUserId: userId });
    throw new PlatformAdminOnlyError();
  }
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "DELETE FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2",
      [userId, groupDn],
    );
    await writeAudit(
      req,
      actorEmail,
      grantsAdmin ? "user.admin_group.remove" : "user.group.remove",
      email,
      { userId, groupDn },
      client,
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  await revokeAllSessions(userId, email);
}

/**
 * Revoke sessions for every current member of a group — the group-wide
 * counterpart to addUserToGroup/removeUserFromGroup/applyAccess above, used
 * after a group-level access change (entitlements, GMS role) since that
 * changes what every member of the group can reach, not just one user.
 * Best-effort per member: one member's revoke failing (e.g. a transient GMS
 * bridge hiccup, already swallowed inside revokeAllSessions itself) must not
 * stop the rest of the group from being revoked.
 */
export async function revokeSessionsForGroupMembers(dn: string): Promise<void> {
  const { rows } = await pool.query<{ id: string; email: string }>(
    "SELECT u.id, u.email FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id WHERE g.group_dn = $1 AND NOT u.is_platform_admin",
    [dn],
  );
  for (const row of rows) {
    await revokeAllSessions(row.id, row.email).catch((err) => {
      logger.error(
        { err, userId: row.id, email: row.email, dn },
        "[idp:admin] group-wide session revoke failed for member",
      );
    });
  }
}

/**
 * Replace a group's App access (idp_app_entitlements) with `requested` (unknown apps are
 * dropped), in one transaction, and report whether the SET actually changed. Shared by the
 * legacy console and the Next console's /api/v1/admin handlers so the two cannot disagree
 * about when members must be signed out (the v1 handler used to skip the diff and the
 * revoke altogether).
 */
export async function replaceGroupEntitlements(
  dn: string,
  requested: string[],
): Promise<{ apps: string[]; changed: boolean }> {
  const apps = [...new Set(requested.filter((rp) => APPS.some((a) => a.rp === rp)))];
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ relying_party: string }>(
      "SELECT relying_party FROM idp_app_entitlements WHERE group_dn = $1",
      [dn],
    );
    const current = new Set(rows.map((r) => r.relying_party));
    const next = new Set(apps);
    const changed =
      current.size !== next.size || [...current].some((rp) => !next.has(rp));
    await client.query("DELETE FROM idp_app_entitlements WHERE group_dn = $1", [dn]);
    for (const rp of apps) {
      await client.query(
        "INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2)",
        [rp, dn],
      );
    }
    await client.query("COMMIT");
    return { apps, changed };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/** Replace a group's GMS role mapping (idp_gms_role_mappings; "" clears it) and report whether
 *  it changed. Shared by both consoles for the same reason as replaceGroupEntitlements. */
export async function replaceGroupGmsRole(
  dn: string,
  role: string,
): Promise<{ changed: boolean }> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rows } = await client.query<{ role_name: string }>(
      "SELECT role_name FROM idp_gms_role_mappings WHERE group_dn = $1",
      [dn],
    );
    const changed = (rows[0]?.role_name ?? "") !== role || rows.length > 1;
    await client.query("DELETE FROM idp_gms_role_mappings WHERE group_dn = $1", [dn]);
    if (role) {
      await client.query(
        "INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        [dn, role],
      );
    }
    await client.query("COMMIT");
    return { changed };
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export async function allGroupDns(requestId?: string): Promise<string[]> {
  const { rows } = await pool.query<{ group_dn: string }>(`
    SELECT group_dn FROM idp_user_groups
    UNION SELECT group_dn FROM idp_app_entitlements
    UNION SELECT group_dn FROM idp_gms_role_mappings
  `);
  const set = new Set(rows.map((r) => r.group_dn));
  if (IDP_CONFIG.dmsInternalApiKey) {
    try {
      (
        await listDmsMappedGroups(IDP_CONFIG.dmsDefaultTenant, requestId)
      ).forEach((dn) => set.add(dn));
    } catch {
      // DMS unreachable — still show what the IdP itself knows about.
    }
  }
  return [...set].sort();
}

/**
 * Groups a user may be added to via the free-text field on their page. Was
 * unvalidated: any admin could type the literal admin-group DN (silent backdoor
 * admin) or another user's personal group DN (cloning their DMS/GMS role).
 * Constrained to groups the system already knows about — plus the admin group
 * itself, since granting IdP Administration access is legitimate, just no
 * longer silent (see the distinct audit action below) — never a personal DN.
 */
export async function addableGroupDns(
  requestId?: string,
): Promise<Set<string>> {
  const dns = (await allGroupDns(requestId)).filter(
    (dn) => !isPersonalGroupDn(dn),
  );
  return new Set([...dns, IDP_CONFIG.adminGroup]);
}

export interface ClientUserSummary {
  id: string;
  email: string;
  givenName: string;
  familyName: string;
  isActive: boolean;
  lastLoginAt: string | null;
  matchedGroups: string[];
}

/**
 * Who can actually reach a given relying party — mirrors portal/catalog.ts's
 * `entitled()`: a user counts for `clientId` if one of their groups
 * (idp_user_groups, kept in sync at login/AD-resync — see ad-resync.worker.ts)
 * has a matching row in idp_app_entitlements, OR that client has no
 * entitlement rows at all (open to every authenticated user, same as the
 * portal launcher's "no rules → open" fallback). This is deliberately NOT
 * based on oidc_artifacts' Grant records — those only exist for
 * accountId/clientId pairs that have completed a live OIDC consent, which in
 * a fresh/dev DB (or for users who haven't logged in since a reset) is far
 * fewer than everyone who is actually entitled to use the app.
 */
export async function usersEntitledToClient(
  clientId: string,
): Promise<ClientUserSummary[]> {
  const { rows: entitlementRows } = await pool.query<{ group_dn: string }>(
    "SELECT group_dn FROM idp_app_entitlements WHERE relying_party = $1",
    [clientId],
  );

  if (entitlementRows.length === 0) {
    // No entitlement rows means "every authenticated user may reach this
    // client" (mirrors portal/catalog.ts's open-by-default rule) — but this
    // used to be an unbounded `SELECT * FROM idp_users`, so any client with no
    // (or not-yet-configured) idp_app_entitlements rows returned literally
    // every SSO account platform-wide on every load. Capped at 500: neither
    // caller of this function threads page/limit params today (the
    // dashboard's per-client userCount at api/v1/admin.router.ts:~200 only
    // needs a count, and its one full-list consumer — GET
    // /clients/:clientId/users — renders the whole result, no pagination UI).
    // Raise this (or thread real page/pageSize params through both call
    // sites) if platform-wide account counts ever approach it.
    const { rows } = await pool.query<{
      id: string;
      email: string;
      given_name: string;
      family_name: string;
      is_active: boolean;
      last_login_at: string | null;
    }>(
      `SELECT id, email, given_name, family_name, is_active, last_login_at
       FROM idp_users WHERE NOT is_platform_admin ORDER BY email ASC
       LIMIT 500`,
    );
    return rows.map((r) => ({
      id: r.id,
      email: r.email,
      givenName: r.given_name,
      familyName: r.family_name,
      isActive: r.is_active,
      lastLoginAt: r.last_login_at,
      matchedGroups: [],
    }));
  }

  const groupDns = entitlementRows.map((r) => r.group_dn);
  const { rows } = await pool.query<{
    id: string;
    email: string;
    given_name: string;
    family_name: string;
    is_active: boolean;
    last_login_at: string | null;
    matched_groups: string[];
  }>(
    `SELECT u.id, u.email, u.given_name, u.family_name, u.is_active, u.last_login_at,
            array_agg(DISTINCT ug.group_dn) AS matched_groups
     FROM idp_users u
     JOIN idp_user_groups ug ON ug.user_id = u.id AND ug.group_dn = ANY($1::text[])
     WHERE NOT u.is_platform_admin
     GROUP BY u.id, u.email, u.given_name, u.family_name, u.is_active, u.last_login_at
     ORDER BY u.email ASC`,
    [groupDns],
  );
  return rows.map((r) => ({
    id: r.id,
    email: r.email,
    givenName: r.given_name,
    familyName: r.family_name,
    isActive: r.is_active,
    lastLoginAt: r.last_login_at,
    matchedGroups: r.matched_groups,
  }));
}
