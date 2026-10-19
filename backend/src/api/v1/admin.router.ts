/**
 * Admin Console API endpoints for the Next.js frontend.
 *
 * Provides JSON data for all admin console pages:
 * - Dashboard statistics
 * - Users management
 * - Groups management
 * - OAuth clients
 * - Active sessions
 * - Login history
 * - Signing keys
 * - Audit log
 */

import { PA_EMAILS_SQL, PA_IDS_SQL, guardPlatformAdminUserParam, isPlatformAdminSession } from "../../auth/platform-admin.js";
import {
  Router,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import crypto from "node:crypto";
import { sendOk, sendError } from "./platform.router.js";
import { requireAdminJson } from "../../admin/requireAdmin.js";
import type { PortalSession } from "../../portal/session.js";
import { runAuditChainCheck } from "../../ops/auditChain.js";
import { PASSWORD_MAX_LENGTH, newPasswordProblem } from "../../auth/password-policy.js";
import { USER_LIMITS, identityProblems, parseOfficeId } from "../../admin/user-input.js";
import { closeRequestsForUser } from "../../auth/reset-requests.js";
import { IDP_CONFIG } from "../../config.js";
import { pool } from "../../db/pool.js";
import {
  listDmsRoleNames,
  listGmsRoleNames,
  listGmsOfficeScopedRoleNames,
} from "../../admin/client-roles.js";
import {
  listGmsOffices,
  GmsInternalApiError,
} from "../../admin/gms-internal-client.js";
import {
  liveDmsStatus,
  liveGmsStatus,
  getAccess,
  resolveDmsPermissions,
  allGroupDns,
  listOffices,
  listDmsDepartmentsForAdmin,
  setDmsDepartmentsForUser,
  roleCatalog,
  addUserToGroup,
  removeUserFromGroup,
  addableGroupDns,
  isPersonalGroupDn,
  assertDmsReadableForAccessSave,
  personalGroupDn,
  applyAccess,
  usersEntitledToClient,
  revokeSessionsForGroupMembers,
  replaceGroupEntitlements,
  replaceGroupGmsRole,
  APPS,
} from "../../admin/access.js";
import { listSigningKeys } from "../../jwks.js";
import {
  listAudit,
  countAudit,
  distinctAuditActions,
  writeAudit,
  MIN_ACK_REASON_LENGTH,
} from "../../admin/audit.js";
import { revokeAllSessions, disableWarning, type RevocationResult } from "../../auth/revoke.js";
import { hashPassword } from "../../auth/password.js";
import { disableTotp } from "../../auth/local-users.js";
import {
  listDmsRoles,
  getDmsRolePermissions,
  putDmsRolePermissions,
  getDmsRoleMapping,
  putDmsRoleMapping,
  putDmsUserDepartments,
  DmsInternalApiError,
} from "../../admin/dms-internal-client.js";
import { resolveUserListQuery } from "../../admin/services/user-query.js";
import { buildLoginFilter } from "../../admin/services/login-filters.js";
import {
  ALL_PERMISSIONS,
  groupedPermissions,
} from "../../admin/dms-permissions.js";
import { withMemberCounts } from "../../admin/services/groups.service.js";
import { loginEventRetentionDays } from "../../ops/retention.js";
import { collectReadiness } from "../../ops/readiness.js";
import { getBool, getNumber } from "../../settings/store.js";
import { reuseOrIssueCsrf } from "../../http/csrf-token.js";
import { selfDisableRefusal, passwordResetRefusal } from "../../admin/user-guards.js";

/** A YYYY-MM-DD string that is a real calendar date, else null. */
export function parseIsoDate(value: unknown): string | null {
  const v = String(value ?? "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const d = new Date(`${v}T00:00:00Z`);
  return Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== v ? null : v;
}

/** The correlation id main.ts's middleware stamped on this request — threaded
 *  into every outbound GMS/DMS internal-API call below, same idiom as
 *  admin/access.ts's identical helper. */
function rid(res: Response): string {
  return String(res.locals.requestId ?? "");
}

async function rollbackFailedUserCreate(
  userId: string,
  email: string,
  sessionEmail: string,
  requestId: string,
): Promise<void> {
  const groupDn = personalGroupDn(userId);
  if (IDP_CONFIG.dmsInternalApiKey) {
    await putDmsRoleMapping(
      IDP_CONFIG.dmsDefaultTenant,
      groupDn,
      [],
      sessionEmail,
      requestId,
    ).catch(() => {});
    await putDmsUserDepartments(
      IDP_CONFIG.dmsDefaultTenant,
      email,
      [],
      sessionEmail,
      requestId,
    ).catch(() => {});
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("DELETE FROM idp_user_groups WHERE user_id = $1", [
      userId,
    ]);
    await client.query("DELETE FROM idp_app_entitlements WHERE group_dn = $1", [
      groupDn,
    ]);
    await client.query(
      "DELETE FROM idp_gms_role_mappings WHERE group_dn = $1",
      [groupDn],
    );
    await client.query("DELETE FROM idp_gms_user_office WHERE email = $1", [
      email.toLowerCase(),
    ]);
    await client.query("DELETE FROM idp_users WHERE id = $1", [userId]);
    await client.query("COMMIT");
  } catch {
    await client.query("ROLLBACK").catch(() => {});
  } finally {
    client.release();
  }
}

/**
 * Answer a failed DMS internal-API call with its own code instead of letting it fall
 * through to Express's opaque 500: ERR-DMS-UNREACHABLE / ERR-DMS-TIMEOUT / ERR-DMS-NOT-
 * CONFIGURED are 503 (retry once DMS is back), a DMS validation answer (404/409/422,
 * e.g. ERR-ROLE-NOT-FOUND for a role DMS does not have) keeps its status, and anything
 * else DMS said (an auth rejection of the shared key) is a 502 so the admin's own
 * session is not mistaken for the failing party. Returns false when `err` is not a DMS
 * error so the caller can hand it on.
 */
export function respondDmsFailure(res: Response, err: unknown): boolean {
  if (!(err instanceof DmsInternalApiError)) return false;
  const status = [404, 409, 422].includes(err.status) ? err.status : err.status === 503 ? 503 : 502;
  sendError(res, status, err.code || "ERR-DMS", err.message);
  return true;
}

/** Extract all cookie values for a given name */
function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i !== -1 && part.slice(0, i).trim() === name) {
      out.push(decodeURIComponent(part.slice(i + 1).trim()));
    }
  }
  return out;
}

// requireAdmin (session lookup, admin-group check, logout-CSRF cookie) now
// lives in admin/requireAdmin.ts — see SSO-F4. This router is the one that
// issues the logout-CSRF cookie, matching its pre-refactor behavior.
const requireAdmin = requireAdminJson(sendError, { issueLogoutCsrf: true });

// Distinct cookie name from the retired console's idp_admin_csrf (it was in admin/csrf.ts,
// Path=/admin) — this API is mounted at /api/v1/admin, a sibling path that
// would never receive a Path=/admin cookie from the browser (see the
// cookie-path-scoping writeup in app/(auth)/interaction/[uid]/actions.ts on
// the frontend side; same class of bug, fixed here by giving this API's CSRF
// cookie its own matching path instead of reusing the EJS one's).
export const ADMIN_API_CSRF_COOKIE = "idp_admin_api_csrf";

/** Issue CSRF token for the Next.js admin console's JSON mutations. */
export function issueAdminCsrf(res: Response): string {
  // Prefixed with publicBasePath, under /sso the console is served at /sso/admin, so the cookie path needs the public base path. Reused while the browser holds one (http/csrf-token.ts):
  // every console page that reads state also issues a token, and two tabs (or a double fetch) must not invalidate each other.
  return reuseOrIssueCsrf(res, ADMIN_API_CSRF_COOKIE, {
    httpOnly: true,
    sameSite: "lax",
    secure: IDP_CONFIG.isProd,
    path: `${IDP_CONFIG.publicBasePath}/api/v1/admin`,
  });
}

/** Double-submit check for the cookie above against the JSON body's `csrf` field. */
export function validateAdminApiCsrf(req: Request): boolean {
  const cookie = cookieValues(req, ADMIN_API_CSRF_COOKIE)[0];
  const submitted = (req.body?.csrf as string) ?? "";
  if (!cookie || !submitted || cookie.length !== submitted.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(submitted));
}

export function adminApiRouter(): Router {
  const router = Router();

  // Apply admin authentication to all routes
  router.use(requireAdmin);

  // The platform administrator does not exist for this console: any /users/:id
  // route that names it answers "user not found" (auth/platform-admin.ts).
  router.param(
    "id",
    guardPlatformAdminUserParam((res) =>
      sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found"),
    ),
  );

  /**
   * GET /api/v1/admin/stats
   * Dashboard statistics
   */
  router.get(
    "/stats",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;

        const [
          { rows: userCountRows },
          groupList,
          { rows: statRows },
          { rows: alertRows },
          clientUserLists,
        ] = await Promise.all([
          pool.query<{ count: string; ad: string }>(
            "SELECT COUNT(*) AS count, COUNT(*) FILTER (WHERE source = 'ad') AS ad FROM idp_users WHERE NOT is_platform_admin",
          ),
          allGroupDns(rid(res)),
          pool.query<{
            sso: string;
            portal: string;
            fails: string;
            audits: string;
          }>(
            `SELECT
             (SELECT COUNT(*) FROM oidc_artifacts WHERE kind = 'Session' AND payload->>'accountId' IS NOT NULL AND payload->>'accountId' NOT IN ${PA_IDS_SQL} AND (expires_at IS NULL OR expires_at > NOW())) AS sso,
             (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'portal' AND coalesce(payload->>'accountId', '') NOT IN ${PA_IDS_SQL} AND expires_at > NOW()) AS portal,
             (SELECT COUNT(*) FROM idp_login_events WHERE success = FALSE AND created_at > NOW() - INTERVAL '24 hours') AS fails,
             (SELECT COUNT(*) FROM idp_admin_audit WHERE created_at > NOW() - INTERVAL '7 days' AND lower(actor_email) NOT IN ${PA_EMAILS_SQL}) AS audits`,
          ),
          pool.query<{ email: string; failures: string }>(
            `SELECT email, COUNT(*) AS failures FROM idp_login_events
           WHERE success = FALSE AND created_at > NOW() - INTERVAL '15 minutes'
           GROUP BY email HAVING COUNT(*) >= 5 ORDER BY failures DESC LIMIT 5`,
          ),
          // Entitlement-based, same rule the portal launcher itself uses
          // (portal/catalog.ts's entitled()) — NOT oidc_artifacts Grant rows,
          // which only exist for users who've completed a live OIDC consent and
          // badly undercount in a fresh/reset DB. Excludes 'portal' itself
          // (not a gated relying party — it's the launcher every authenticated
          // user reaches) and skips any client no longer in the live seed
          // (e.g. a stale idp_clients row left behind by a reverted rollout).
          Promise.all(
            IDP_CONFIG.clientSeed
              .filter((c) => c.client_id !== "portal")
              .map(async (c) => ({
                clientId: c.client_id,
                name: c.name,
                userCount: (await usersEntitledToClient(c.client_id)).length,
              })),
          ),
        ]);

        sendOk(res, {
          adminEmail: session.email,
          // Every account (local and Active Directory) except the platform administrator.
          userCount: parseInt(userCountRows[0].count),
          adUserCount: parseInt(userCountRows[0].ad),
          groupCount: groupList.length,
          dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
          // ready / degraded / not_ready: the dashboard banner (details are on the System page).
          health: (await collectReadiness()).status,
          stats: {
            sso: parseInt(statRows[0].sso),
            portal: parseInt(statRows[0].portal),
            fails: parseInt(statRows[0].fails),
            audits: parseInt(statRows[0].audits),
          },
          alerts: alertRows.map((row) => ({
            email: row.email,
            failures: parseInt(row.failures),
          })),
          clientUserCounts: clientUserLists,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/users
   * List users with pagination, search, filters (status, source, two-factor, client, role) and a sort.
   * The query is understood by admin/services/user-query.ts, shared with the CSV export so both always mean the same list.
   */
  router.get(
    "/users",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        const resolved = await resolveUserListQuery(req.query as Record<string, unknown>, rid(res));
        if (!resolved.ok) {
          sendError(res, resolved.status, resolved.code, resolved.message);
          return;
        }
        const { filter, orderBy, view } = resolved;
        const PAGE_SIZE = [20, 50, 100].includes(Number(req.query.pageSize)) ? Number(req.query.pageSize) : 20;
        const page = Math.max(1, Number(req.query.page) || 1);
        const limitParam = filter.params.length + 1;
        const offsetParam = filter.params.length + 2;

        const [{ rows: users }, { rows: countRows }] = await Promise.all([
          pool.query(
            `SELECT u.id, u.email, u.given_name, u.family_name, u.is_active, u.source, u.last_login_at, u.created_at,
                  u.totp_enabled, u.must_change_password,
                  (SELECT COUNT(*) FROM idp_user_groups g WHERE g.user_id = u.id) AS group_count
           FROM idp_users u
           ${filter.where}
           ORDER BY ${orderBy}
           LIMIT $${limitParam} OFFSET $${offsetParam}`,
            [...filter.params, PAGE_SIZE, (page - 1) * PAGE_SIZE],
          ),
          pool.query<{ count: string }>(`SELECT COUNT(*) FROM idp_users u ${filter.where}`, filter.params),
        ]);

        const total = Number(countRows[0].count);

        sendOk(res, {
          users,
          pagination: {
            page,
            pageSize: PAGE_SIZE,
            total,
            totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
          },
          query: view.q,
          filters: { status: view.status, source: view.source, mfa: view.mfa, client: view.client, role: view.role },
          sort: { key: view.sort, dir: view.dir },
          adminEmail: session.email,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/users/:id
   * Get detailed user information
   */
  router.get(
    "/users/:id",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;

        const { rows: userRows } = await pool.query(
          `SELECT id, email, email_verified, given_name, family_name, is_active, source,
                must_change_password, totp_enabled, failed_logins, locked_until,
                last_login_at, created_at, updated_at
         FROM idp_users WHERE id = $1`,
          [req.params.id],
        );

        const user = userRows[0];
        if (!user) {
          sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
          return;
        }

        const personalDn = personalGroupDn(user.id);
        const [
          { rows: groups },
          { rows: history },
          knownGroups,
          access,
          officesResult,
          dmsDepartmentsResult,
          liveGms,
          catalog,
        ] = await Promise.all([
          pool.query<{ group_dn: string }>(
            "SELECT group_dn FROM idp_user_groups WHERE user_id = $1 ORDER BY group_dn",
            [user.id],
          ),
          pool.query(
            `SELECT actor_email, action, detail, created_at FROM idp_admin_audit
           WHERE target = $1 OR detail->>'userId' = $2
           ORDER BY id DESC LIMIT 20`,
            [user.email, user.id],
          ),
          allGroupDns(rid(res)),
          getAccess(personalDn, user.email, rid(res)),
          listOffices(rid(res)),
          listDmsDepartmentsForAdmin(rid(res)),
          liveGmsStatus(user.email, rid(res)),
          roleCatalog(),
        ]);

        const isAdmin = groups.some(
          (g) => g.group_dn === IDP_CONFIG.adminGroup,
        );
        const liveDms = await liveDmsStatus(user.email, rid(res));
        // The person's own recent sign-in attempts (so an administrator helping them can see what happened) and how many two-factor
        // recovery codes they still hold (a count only; the codes are never readable).
        const [{ rows: recentLogins }, { rows: codeRows }] = await Promise.all([
          pool.query(
            `SELECT success, reason, ip, user_agent, created_at FROM idp_login_events WHERE email = $1 ORDER BY id DESC LIMIT 8`,
            [String(user.email).toLowerCase()],
          ),
          pool.query<{ n: string }>(
            "SELECT COUNT(*) AS n FROM idp_recovery_codes WHERE user_id = $1 AND used_at IS NULL",
            [user.id],
          ),
        ]);

        let dmsPermissions: Awaited<
          ReturnType<typeof resolveDmsPermissions>
        > | null = null;
        let dmsPermissionsError: string | null = null;
        if (access.dmsRoles.length > 0 && liveDms.exists && liveDms.id) {
          try {
            dmsPermissions = await resolveDmsPermissions(
              access.dmsRoles,
              liveDms.id,
              rid(res),
            );
          } catch (err) {
            dmsPermissionsError =
              err instanceof DmsInternalApiError
                ? err.message
                : "Could not reach the DMS internal API.";
          }
        }

        // Portal access for this one person: the entitlements held by their personal group (the same table the group page edits).
        const { rows: entitledRows } = await pool.query<{ relying_party: string }>(
          "SELECT relying_party FROM idp_app_entitlements WHERE group_dn = $1 ORDER BY relying_party",
          [personalDn],
        );

        sendOk(res, {
          user,
          personalDn,
          entitledApps: entitledRows.map((r) => r.relying_party),
          appCatalog: APPS,
          groups: groups
            .map((g) => g.group_dn)
            .filter((dn) => dn !== personalDn),
          knownGroups: [...new Set([...knownGroups, IDP_CONFIG.adminGroup])]
            .filter((dn) => !isPersonalGroupDn(dn))
            .sort(),
          isAdmin,
          // Who is an IdP administrator is the platform administrator's call alone;
          // the page disables the checkbox for everyone else and says why.
          canChangeAdminGroup: await isPlatformAdminSession(session),
          // The console refuses to disable your own account; the page greys the button out.
          isSelf: user.id === session.accountId,
          liveDms,
          liveGms,
          access,
          offices: officesResult.offices,
          officesError: officesResult.error,
          dmsDepartments: dmsDepartmentsResult.departments,
          dmsDepartmentsError: dmsDepartmentsResult.error,
          dmsPermissions: dmsPermissions
            ? { ...dmsPermissions, effective: [...dmsPermissions.effective] }
            : null,
          dmsPermissionsError,
          dmsPermissionGroups: groupedPermissions(),
          dmsRoles: catalog.dmsRoles,
          gmsRoles: catalog.gmsRoles,
          gmsOfficeScopedRoles: catalog.gmsOfficeScopedRoles,
          dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
          history,
          recentLogins,
          // A lock only means something while lockout is switched on (platform setting) and its time has not passed.
          isLocked: getBool("lockout.enabled") && Boolean(user.locked_until) && new Date(user.locked_until).getTime() > Date.now(),
          recoveryCodesRemaining: Number(codeRows[0]?.n ?? 0),
          // The temporary-password form states the real rule (a platform setting) instead of a hard-coded 8.
          passwordMinLength: getNumber("password.minLength"),
          adminEmail: session.email,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users
   * Create a new local user
   */
  router.post(
    "/users",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const catalog = await roleCatalog();
        const email = String(req.body.email ?? "")
          .trim()
          .toLowerCase();
        const givenName = String(req.body.given_name ?? "").trim();
        const familyName = String(req.body.family_name ?? "").trim();
        const password = String(req.body.password ?? "");
        const dmsRoles = ([] as unknown[])
          .concat(req.body.dms_role ?? [])
          .map((r) => String(r))
          .filter((r) => catalog.dmsRoles.includes(r));
        const gmsRole = catalog.gmsRoles.includes(
          String(req.body.gms_role ?? ""),
        )
          ? String(req.body.gms_role)
          : "";
        const parsedOffice = parseOfficeId(req.body.office_id);
        if (parsedOffice === "bad") {
          sendError(res, 400, "ERR-VALIDATION-FAILED", "Choose an office from the list.", [{ field: "office_id", message: "Choose an office from the list." }]);
          return;
        }
        const officeId = parsedOffice;
        const dmsDepartmentIds: string[] = Array.from(
          new Set<string>(
            (Array.isArray(req.body.dms_department_ids)
              ? req.body.dms_department_ids
              : []
            ).map((value: unknown) => String(value)),
          ),
        );

        if (!email || !password) {
          sendError(res, 400, "ERR-VALIDATION-FAILED", "Email and a temporary password are required.");
          return;
        }
        const identityIssues = identityProblems({ email, givenName, familyName });
        if (identityIssues.length > 0) {
          sendError(res, 400, "ERR-VALIDATION-FAILED", identityIssues[0].message, identityIssues);
          return;
        }
        // The platform password rules (Admin > Settings) apply to a temporary password too: an easily guessed one is the weakest moment an account has.
        const passwordProblem = newPasswordProblem(password, email);
        if (passwordProblem) {
          sendError(res, 400, "ERR-VALIDATION-FAILED", passwordProblem);
          return;
        }
        if (catalog.gmsOfficeScopedRoles.includes(gmsRole) && !officeId) {
          sendError(
            res,
            400,
            "ERR-OFFICE-REQUIRED",
            `GMS role "${gmsRole}" requires an office — pick one.`,
          );
          return;
        }
        if (dmsDepartmentIds.length > 0 && dmsRoles.length === 0) {
          sendError(
            res,
            400,
            "ERR-DMS-DEPARTMENT-NO-ROLE",
            "Select at least one DMS role before assigning departments.",
          );
          return;
        }

        // The password the administrator types is a temporary one: the person is forced to
        // choose their own at first sign-in (must_change_password, below), so the
        // administrator does not keep a working credential for the account.
        const pwd = await hashPassword(password);
        let userId: string;
        try {
          const { rows } = await pool.query<{ id: string }>(
            `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, must_change_password)
           VALUES ($1, TRUE, $2, $3, $4, 'local', TRUE, TRUE)
           RETURNING id`,
            [email, givenName, familyName, pwd],
          );
          userId = rows[0].id;
        } catch (err: unknown) {
          if (
            err &&
            typeof err === "object" &&
            "code" in err &&
            (err as { code: string }).code === "23505"
          ) {
            sendError(
              res,
              409,
              "ERR-EMAIL-EXISTS",
              "A user with that email already exists.",
            );
            return;
          }
          throw err;
        }

        try {
          if (dmsRoles.length > 0 || gmsRole) {
            await applyAccess(
              userId,
              email,
              personalGroupDn(userId),
              dmsRoles,
              gmsRole,
              officeId,
              session.email,
              req,
              rid(res),
            );
          }
          if (dmsDepartmentIds.length > 0) {
            await setDmsDepartmentsForUser(
              email,
              dmsDepartmentIds,
              session.email,
              rid(res),
            );
          }
          await writeAudit(req, session.email, "user.create", email, {
            userId,
            dmsRoles,
            gmsRole,
            officeId,
          });
        } catch (err) {
          await rollbackFailedUserCreate(
            userId,
            email,
            session.email,
            rid(res),
          );
          throw err;
        }
        sendOk(res, { id: userId });
      } catch (err) {
        if (!respondDmsFailure(res, err)) next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/access
   */
  router.post(
    "/users/:id/access",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        if (userId === session.accountId) {
          sendError(
            res,
            403,
            "ERR-SELF-SERVICE",
            "You cannot change your own DMS/GMS access — ask another admin.",
          );
          return;
        }
        const { rows } = await pool.query<{ email: string }>(
          "SELECT email FROM idp_users WHERE id = $1",
          [userId],
        );
        if (!rows[0]) {
          sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
          return;
        }

        // An ABSENT field must not read as "no roles": applyAccess would replace the user's DMS mapping with an empty one
        // and clear their GMS role (the same wipe the legacy form had). The page always sends both; anything else is a bug
        // or a stale client, so refuse instead of guessing.
        if (req.body.dms_role === undefined || req.body.gms_role === undefined) {
          sendError(res, 422, "ERR-ACCESS-INCOMPLETE", "dms_role and gms_role must both be sent (use [] and \"\" to remove access).");
          return;
        }
        const catalog = await roleCatalog();
        const dmsRoles = ([] as unknown[])
          .concat(req.body.dms_role ?? [])
          .map((r) => String(r))
          .filter((r) => catalog.dmsRoles.includes(r));
        const gmsRole = catalog.gmsRoles.includes(
          String(req.body.gms_role ?? ""),
        )
          ? String(req.body.gms_role)
          : "";
        const parsedOffice = parseOfficeId(req.body.office_id);
        if (parsedOffice === "bad") {
          sendError(res, 400, "ERR-VALIDATION-FAILED", "Choose an office from the list.", [{ field: "office_id", message: "Choose an office from the list." }]);
          return;
        }
        const officeId = parsedOffice;
        const dmsDepartmentIds: string[] = Array.from(
          new Set<string>(
            (Array.isArray(req.body.dms_department_ids)
              ? req.body.dms_department_ids
              : []
            ).map((value: unknown) => String(value)),
          ),
        );

        if (catalog.gmsOfficeScopedRoles.includes(gmsRole) && !officeId) {
          sendError(
            res,
            400,
            "ERR-OFFICE-REQUIRED",
            `GMS role "${gmsRole}" requires an office to be selected.`,
          );
          return;
        }

        if (dmsDepartmentIds.length > 0 && dmsRoles.length === 0) {
          sendError(
            res,
            400,
            "ERR-DMS-DEPARTMENT-NO-ROLE",
            "Select at least one DMS role before assigning departments.",
          );
          return;
        }
        {
          // Who is an IdP administrator belongs to the platform administrator alone.
          // Checked up front so a refusal leaves nothing half-applied.
          const wantsAdminEarly =
            req.body.is_admin === true ||
            req.body.is_admin === "on" ||
            req.body.is_admin === "true";
          const { rows: adminNow } = await pool.query(
            "SELECT 1 FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2",
            [userId, IDP_CONFIG.adminGroup],
          );
          if (wantsAdminEarly !== adminNow.length > 0 && !(await isPlatformAdminSession(session))) {
            sendError(res, 403, "ERR-PLATFORM-ADMIN-ONLY", "Only the platform administrator can change who is an IdP administrator.");
            return;
          }
        }
        const previousDms = await liveDmsStatus(rows[0].email, rid(res));
        const previousDepartmentIds = previousDms.exists
          ? previousDms.departmentIds
          : previousDms.pendingDepartmentIds;
        // Only when the caller actually sent a department list: an absent field used to
        // read as "no departments" and silently emptied the user's DMS memberships.
        const departmentsProvided = Array.isArray(req.body.dms_department_ids);
        if (departmentsProvided) {
          await setDmsDepartmentsForUser(
            rows[0].email,
            dmsDepartmentIds,
            session.email,
            rid(res),
          );
        }
        try {
          await assertDmsReadableForAccessSave(personalGroupDn(userId), rid(res));
        } catch (err) {
          if (!respondDmsFailure(res, err)) throw err;
          return;
        }
        try {
          await applyAccess(
            userId,
            rows[0].email,
            personalGroupDn(userId),
            dmsRoles,
            gmsRole,
            officeId,
            session.email,
            req,
            rid(res),
          );
        } catch (err) {
          if (departmentsProvided) {
            await setDmsDepartmentsForUser(
              rows[0].email,
              previousDepartmentIds,
              session.email,
              rid(res),
            ).catch(() => {});
          }
          throw err;
        }
        await writeAudit(req, session.email, "user.access", rows[0].email, {
          userId,
          dmsRoles,
          gmsRole,
          officeId,
        });

        const wantsAdmin =
          req.body.is_admin === true ||
          req.body.is_admin === "on" ||
          req.body.is_admin === "true";
        const { rows: adminMembership } = await pool.query(
          "SELECT 1 FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2",
          [userId, IDP_CONFIG.adminGroup],
        );
        const isCurrentlyAdmin = adminMembership.length > 0;
        if (wantsAdmin && !isCurrentlyAdmin) {
          await addUserToGroup(
            userId,
            rows[0].email,
            IDP_CONFIG.adminGroup,
            session.email,
            req,
          );
        } else if (!wantsAdmin && isCurrentlyAdmin) {
          await removeUserFromGroup(
            userId,
            rows[0].email,
            IDP_CONFIG.adminGroup,
            session.email,
            req,
          );
        }

        sendOk(res, { ok: true });
      } catch (err) {
        if (!respondDmsFailure(res, err)) next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/dms-permissions
   */
  router.post(
    "/users/:id/dms-permissions",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        if (userId === session.accountId) {
          sendError(
            res,
            403,
            "ERR-SELF-SERVICE",
            "You cannot change your own DMS permissions — ask another admin.",
          );
          return;
        }
        const { rows } = await pool.query<{ email: string }>(
          "SELECT email FROM idp_users WHERE id = $1",
          [userId],
        );
        if (!rows[0]) {
          sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
          return;
        }
        const email = rows[0].email;

        const access = await getAccess(
          personalGroupDn(userId),
          email,
          rid(res),
        );
        if (access.dmsRoles.length === 0) {
          sendError(
            res,
            400,
            "ERR-NO-DMS-ROLE",
            "This user has no DMS role — set one under System access assigned by SSO first.",
          );
          return;
        }
        const liveDms = await liveDmsStatus(email, rid(res));
        if (!liveDms.exists || !liveDms.id) {
          sendError(
            res,
            400,
            "ERR-NOT-PROVISIONED",
            "This user does not exist in DMS yet — permissions can only be customized after their first DMS sign-in.",
          );
          return;
        }

        let state: Awaited<ReturnType<typeof resolveDmsPermissions>>;
        try {
          state = await resolveDmsPermissions(
            access.dmsRoles,
            liveDms.id,
            rid(res),
          );
        } catch (err) {
          const message =
            err instanceof DmsInternalApiError
              ? err.message
              : "Could not reach the DMS internal API.";
          sendError(
            res,
            err instanceof DmsInternalApiError ? err.status : 503,
            "ERR-DMS",
            message,
          );
          return;
        }

        const validPermissions = new Set(ALL_PERMISSIONS);
        const checked = new Set(
          ([] as string[])
            .concat(req.body.permissions ?? [])
            .filter((p) => validPermissions.has(p)),
        );
        const roleDefaults = new Set(state.roleDefaults);
        const grants = [...checked].filter((p) => !roleDefaults.has(p));
        const revokes = [...roleDefaults].filter((p) => !checked.has(p));

        try {
          const { putDmsUserOverrides } =
            await import("../../admin/dms-internal-client.js");
          const overrides = await putDmsUserOverrides(
            IDP_CONFIG.dmsDefaultTenant,
            liveDms.id,
            grants,
            revokes,
            session.email,
            rid(res),
          );
          await writeAudit(req, session.email, "user.dms_permissions", email, {
            userId,
            dmsUserId: liveDms.id,
            dmsRoles: access.dmsRoles,
            grants: overrides.grants,
            revokes: overrides.revokes,
          });
        } catch (err) {
          const message =
            err instanceof DmsInternalApiError
              ? `DMS rejected the permission update: ${err.message}`
              : "Could not reach the DMS internal API.";
          sendError(
            res,
            err instanceof DmsInternalApiError ? err.status : 503,
            "ERR-DMS",
            message,
          );
          return;
        }

        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/toggle-active
   */
  router.post(
    "/users/:id/toggle-active",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        const selfRefusal = selfDisableRefusal(session.accountId, userId);
        if (selfRefusal) {
          sendError(res, 403, "ERR-SELF-SERVICE", selfRefusal);
          return;
        }
        let lastRevocation: RevocationResult | null = null;
        const { rows } = await pool.query<{
          email: string;
          is_active: boolean;
        }>(
          "UPDATE idp_users SET is_active = NOT is_active, updated_at = NOW() WHERE id = $1 RETURNING email, is_active",
          [userId],
        );
        if (rows[0]) {
          const revoked = rows[0].is_active
            ? null
            : await revokeAllSessions(userId, rows[0].email);
          lastRevocation = revoked;
          await writeAudit(
            req,
            session.email,
            rows[0].is_active ? "user.enable" : "user.disable",
            rows[0].email,
            revoked ? { userId, revoked } : { userId },
          );
        }
        // Saying "disabled" while a system might still hold a live session would mislead:
        // surface the one case where the account is not yet dark everywhere.
        const warning = rows[0] && !rows[0].is_active ? disableWarning(lastRevocation) : null;
        sendOk(res, { ok: true, isActive: rows[0]?.is_active ?? null, ...(warning ? { warning } : {}) });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/reset-password
   */
  router.post(
    "/users/:id/reset-password",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        const password = String(req.body.password ?? "");
        const { rows } = await pool.query<{ email: string; source: string }>(
          "SELECT email, source FROM idp_users WHERE id = $1",
          [userId],
        );
        if (!rows[0]) {
          sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
          return;
        }
        const passwordProblem = newPasswordProblem(password, rows[0].email);
        if (passwordProblem) {
          sendError(res, 400, "ERR-VALIDATION-FAILED", passwordProblem);
          return;
        }
        const adRefusal = passwordResetRefusal(rows[0].source);
        if (adRefusal) {
          sendError(res, 409, "ERR-AD-ACCOUNT", adRefusal);
          return;
        }

        await pool.query(
          `UPDATE idp_users
         SET password_hash = $2, must_change_password = TRUE, failed_logins = 0, locked_until = NULL, login_failures_cleared_at = NOW(), updated_at = NOW()
         WHERE id = $1`,
          [userId, await hashPassword(password)],
        );
        const revoked = await revokeAllSessions(userId, rows[0].email);
        // Their "I forgot my password" request, if they made one, is done.
        await closeRequestsForUser(userId, (await isPlatformAdminSession(session)) ? "platform" : session.email);
        await writeAudit(
          req,
          session.email,
          "user.password_reset",
          rows[0].email,
          { userId, revoked },
        );
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/mfa-reset
   */
  router.post(
    "/users/:id/mfa-reset",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        const { rows } = await pool.query<{ email: string }>(
          "SELECT email FROM idp_users WHERE id = $1",
          [userId],
        );
        if (!rows[0]) {
          sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
          return;
        }
        await disableTotp(userId);
        await writeAudit(req, session.email, "user.mfa_reset", rows[0].email, {
          userId,
        });
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/groups — add to a shared group
   */
  router.post(
    "/users/:id/groups",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        const groupDn = String(req.body.group_dn ?? "").trim();
        if (groupDn) {
          const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
          if (grantsAdmin) {
            if (!(await isPlatformAdminSession(session))) {
              sendError(res, 403, "ERR-PLATFORM-ADMIN-ONLY", "Only the platform administrator can change who is an IdP administrator.");
              return;
            }
          }
          const allowed = await addableGroupDns(rid(res));
          if (!allowed.has(groupDn)) {
            sendError(
              res,
              400,
              "ERR-UNKNOWN-GROUP",
              "Not a recognized group — configure its access on the Groups page first.",
            );
            return;
          }
          if (userId === session.accountId) {
            const groupAccess = await getAccess(groupDn, undefined, rid(res));
            const grantsAppRole =
              groupAccess.dmsRoles.length > 0 || Boolean(groupAccess.gmsRole);
            if (grantsAdmin || grantsAppRole) {
              sendError(
                res,
                403,
                "ERR-SELF-SERVICE",
                "You cannot grant yourself elevated access — ask another admin.",
              );
              return;
            }
          }
          const { rows } = await pool.query<{ email: string }>(
            "SELECT email FROM idp_users WHERE id = $1",
            [userId],
          );
          if (!rows[0]) {
            sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
            return;
          }
          await addUserToGroup(
            userId,
            rows[0].email,
            groupDn,
            session.email,
            req,
          );
        }
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/users/:id/groups/remove
   */
  router.post(
    "/users/:id/groups/remove",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const userId = String(req.params.id);
        const groupDn = String(req.body.group_dn ?? "");
        if (groupDn === IDP_CONFIG.adminGroup && !(await isPlatformAdminSession(session))) {
          sendError(res, 403, "ERR-PLATFORM-ADMIN-ONLY", "Only the platform administrator can change who is an IdP administrator.");
          return;
        }
        const { rows } = await pool.query<{ email: string }>(
          "SELECT email FROM idp_users WHERE id = $1",
          [userId],
        );
        if (!rows[0]) {
          sendError(res, 404, "ERR-USER-NOT-FOUND", "User not found");
          return;
        }
        await removeUserFromGroup(
          userId,
          rows[0].email,
          groupDn,
          session.email,
          req,
        );
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/groups
   * List all groups
   */
  router.get(
    "/groups",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        // `q` narrows by a case-insensitive piece of the group name (its DN). Bounded: it is only ever compared in memory.
        const q = String(req.query.q ?? "").trim().slice(0, 100).toLowerCase();
        const allDns = (await allGroupDns(rid(res))).filter(
          (dn) => !isPersonalGroupDn(dn) && (!q || dn.toLowerCase().includes(q)),
        );
        // In-memory pagination: allGroupDns() unions three separate sources
        // (idp_user_groups, idp_app_entitlements, idp_gms_role_mappings, plus
        // DMS-mapped groups) with no single paginatable query behind it, so
        // this bounds the RESPONSE size and gives the frontend real page
        // controls without restructuring that union into a paginated query.
        const pageSize = Math.min(
          200,
          Math.max(1, Number(req.query.limit) || 50),
        );
        const page = Math.max(1, Number(req.query.page) || 1);
        const total = allDns.length;
        const pageDns = allDns.slice((page - 1) * pageSize, page * pageSize);

        // Which applications each listed group opens, so the list says what a group is for without opening every one.
        const { rows: entRows } = pageDns.length
          ? await pool.query<{ group_dn: string; relying_party: string }>(
              "SELECT group_dn, relying_party FROM idp_app_entitlements WHERE group_dn = ANY($1::text[]) ORDER BY relying_party",
              [pageDns],
            )
          : { rows: [] as Array<{ group_dn: string; relying_party: string }> };
        const appsByGroup = new Map<string, Array<{ rp: string; label: string }>>();
        for (const e of entRows) {
          const label = APPS.find((a) => a.rp === e.relying_party)?.label ?? e.relying_party;
          appsByGroup.set(e.group_dn, [...(appsByGroup.get(e.group_dn) ?? []), { rp: e.relying_party, label }]);
        }

        // P2-2 / P2-9 item 6: shared with admin/access.ts.
        sendOk(res, {
          groups: (await withMemberCounts(pageDns)).map((g) => ({ ...g, apps: appsByGroup.get(g.dn) ?? [] })),
          filters: { q },
          pagination: {
            page,
            pageSize,
            total,
            totalPages: Math.max(1, Math.ceil(total / pageSize)),
          },
          adminEmail: session.email,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/groups/detail?dn=...
   */
  router.get(
    "/groups/detail",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        const dn = String(req.query.dn ?? "");
        if (!dn) {
          sendError(res, 400, "ERR-MISSING-DN", "dn query param is required");
          return;
        }

        const [{ rows: members }, { rows: entRows }, accessState, catalog] =
          await Promise.all([
            pool.query<{ id: string; email: string }>(
              "SELECT u.id, u.email FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id WHERE g.group_dn = $1 AND NOT u.is_platform_admin ORDER BY u.email",
              [dn],
            ),
            pool.query<{ relying_party: string }>(
              "SELECT relying_party FROM idp_app_entitlements WHERE group_dn = $1",
              [dn],
            ),
            getAccess(dn, undefined, rid(res)),
            roleCatalog(),
          ]);

        sendOk(res, {
          dn,
          members,
          entitled: [...entRows.map((r) => r.relying_party)],
          apps: APPS,
          // Roles this group currently asserts (0, 1 or many) vs. the full
          // catalog of role names the multi-select picker offers.
          selectedDmsRoles: accessState.dmsRoles,
          dmsError: accessState.dmsError,
          dmsRoles: catalog.dmsRoles,
          gmsRole: accessState.gmsRole,
          gmsRoles: catalog.gmsRoles,
          adminEmail: session.email,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/groups/entitlements
   */
  router.post(
    "/groups/entitlements",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const dn = String(req.body.dn ?? "");
        // Separation of duties: the per-user access check protects the user's own page, but these group routes took any dn,
        // including the administrator's own personal group or a group they belong to - a way to widen their own access.
        if ((dn === personalGroupDn(session.accountId) || session.groups.includes(dn)) && !(await isPlatformAdminSession(session))) {
          sendError(res, 403, "ERR-SELF-SERVICE", "You cannot change the access of a group you belong to - ask another administrator.");
          return;
        }
        // Same rule as the legacy console (admin/access.ts): a real change to which apps
        // a group reaches signs its members out, so a removed entitlement takes effect
        // now rather than whenever each member's tokens expire; a no-op re-save does not.
        const { apps: selected, changed } = await replaceGroupEntitlements(
          dn,
          ([] as string[]).concat(req.body.rp ?? []),
        );
        await writeAudit(req, session.email, "group.entitlements", dn, {
          apps: selected,
        });
        if (changed) {
          await revokeSessionsForGroupMembers(dn);
        }
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/groups/dms-role
   */
  router.post(
    "/groups/dms-role",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const dn = String(req.body.dn ?? "");
        // Separation of duties: the per-user access check protects the user's own page, but these group routes took any dn,
        // including the administrator's own personal group or a group they belong to - a way to widen their own access.
        if ((dn === personalGroupDn(session.accountId) || session.groups.includes(dn)) && !(await isPlatformAdminSession(session))) {
          sendError(res, 403, "ERR-SELF-SERVICE", "You cannot change the access of a group you belong to - ask another administrator.");
          return;
        }
        // A group can assert more than one DMS role at once now — the frontend
        // sends `roles: string[]`; a bare `role` string is still accepted for
        // any older caller, normalized to a one-element (or empty) array.
        const roles =
          req.body.roles !== undefined
            ? ([] as unknown[])
                .concat(req.body.roles)
                .map((r) => String(r))
                .filter(Boolean)
            : ([] as unknown[])
                .concat(req.body.role ?? [])
                .map((r) => String(r))
                .filter(Boolean);
        if (!IDP_CONFIG.dmsInternalApiKey) {
          sendError(
            res,
            503,
            "ERR-DMS-NOT-CONFIGURED",
            "DMS_INTERNAL_API_KEY is not configured.",
          );
          return;
        }

        const sortedEq = (a: string[], b: string[]) =>
          a.length === b.length &&
          [...a].sort().every((v, i) => v === [...b].sort()[i]);
        const currentDmsRoles = await getDmsRoleMapping(
          IDP_CONFIG.dmsDefaultTenant,
          dn,
          rid(res),
        )
          .then((m) => m.roleNames)
          .catch(() => null);
        const dmsRoleChanged =
          currentDmsRoles === null || !sortedEq(currentDmsRoles, roles);

        await putDmsRoleMapping(
          IDP_CONFIG.dmsDefaultTenant,
          dn,
          roles,
          session.email,
          rid(res),
        );
        await writeAudit(req, session.email, "group.dms_role", dn, { roles });
        // FIX: this endpoint never forced a re-login for the group's existing
        // members on a role change — DMS only re-derives a user's role set at
        // their next OIDC login (see auth.service.ts's completeOidcCallback),
        // so without this, anyone already signed in kept their old DMS role
        // for the rest of their refresh-token lifetime after an admin changed
        // it here. Same fail-safe as applyAccess(): treat an unreadable prior
        // mapping as "changed" rather than silently skip the revoke.
        if (dmsRoleChanged) {
          await revokeSessionsForGroupMembers(dn);
        }
        sendOk(res, { ok: true });
      } catch (err) {
        if (!respondDmsFailure(res, err)) next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/groups/gms-role
   */
  router.post(
    "/groups/gms-role",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const dn = String(req.body.dn ?? "");
        // Separation of duties: the per-user access check protects the user's own page, but these group routes took any dn,
        // including the administrator's own personal group or a group they belong to - a way to widen their own access.
        if ((dn === personalGroupDn(session.accountId) || session.groups.includes(dn)) && !(await isPlatformAdminSession(session))) {
          sendError(res, 403, "ERR-SELF-SERVICE", "You cannot change the access of a group you belong to - ask another administrator.");
          return;
        }
        const role = String(req.body.role ?? "");
        const { changed } = await replaceGroupGmsRole(dn, role);
        await writeAudit(req, session.email, "group.gms_role", dn, {
          role: role || null,
        });
        // A changed GMS role changes every member's GMS access: sign them out so it
        // applies now (same as the legacy console).
        if (changed) {
          await revokeSessionsForGroupMembers(dn);
        }
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/dms-roles
   */
  router.get(
    "/dms-roles",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        let roles: Awaited<ReturnType<typeof listDmsRoles>> = [];
        let error: string | null = null;
        try {
          roles = await listDmsRoles(IDP_CONFIG.dmsDefaultTenant, rid(res));
        } catch (err) {
          error =
            err instanceof DmsInternalApiError
              ? err.message
              : "Could not reach the DMS internal API.";
        }
        sendOk(res, {
          roles,
          error,
          tenant: IDP_CONFIG.dmsDefaultTenant,
          adminEmail: session.email,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/dms-roles/detail?roleId=...
   */
  router.get(
    "/dms-roles/detail",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        const roleId = String(req.query.roleId ?? "");
        if (!roleId) {
          sendError(
            res,
            400,
            "ERR-MISSING-ROLE-ID",
            "roleId query param is required",
          );
          return;
        }
        let roleName = "";
        let checked: string[] = [];
        let error: string | null = null;
        try {
          const result = await getDmsRolePermissions(
            IDP_CONFIG.dmsDefaultTenant,
            roleId,
            rid(res),
          );
          roleName = result.roleName;
          checked = result.permissions;
        } catch (err) {
          error =
            err instanceof DmsInternalApiError
              ? err.message
              : "Could not reach the DMS internal API.";
        }
        sendOk(res, {
          roleId,
          roleName,
          error,
          checked,
          groups: groupedPermissions(),
          tenant: IDP_CONFIG.dmsDefaultTenant,
          adminEmail: session.email,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * POST /api/v1/admin/dms-roles/detail
   */
  router.post(
    "/dms-roles/detail",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        if (!validateAdminApiCsrf(req)) {
          sendError(
            res,
            403,
            "ERR-INVALID-CSRF",
            "Invalid form submission — please retry.",
          );
          return;
        }
        const session = (req as any).adminSession as PortalSession;
        const roleId = String(req.body.roleId ?? "");
        if (!roleId) {
          sendError(res, 400, "ERR-MISSING-ROLE-ID", "roleId is required");
          return;
        }
        const validPermissions = new Set(ALL_PERMISSIONS);
        const selected = ([] as string[])
          .concat(req.body.permissions ?? [])
          .filter((p) => validPermissions.has(p));
        try {
          await putDmsRolePermissions(
            IDP_CONFIG.dmsDefaultTenant,
            roleId,
            selected,
            session.email,
            rid(res),
          );
        } catch (err) {
          const message =
            err instanceof DmsInternalApiError
              ? `DMS rejected the permission update: ${err.message}`
              : "Could not reach the DMS internal API.";
          sendError(
            res,
            err instanceof DmsInternalApiError ? err.status : 503,
            "ERR-DMS",
            message,
          );
          return;
        }
        await writeAudit(req, session.email, "dms_role.permissions", roleId, {
          roleId,
          permissions: selected,
        });
        sendOk(res, { ok: true });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/clients/:clientId/users
   * Detailed list of users entitled to one relying party (same rule as the
   * portal launcher — see usersEntitledToClient's doc comment).
   */
  router.get(
    "/clients/:clientId/users",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const clientId = String(req.params.clientId);
        const client = IDP_CONFIG.clientSeed.find(
          (c) => c.client_id === clientId,
        );
        if (!client) {
          sendError(res, 404, "not_found", `Unknown client "${clientId}".`);
          return;
        }
        const users = await usersEntitledToClient(clientId);
        sendOk(res, { clientId, name: client.name, users });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/sessions
   * List active sessions
   */
  router.get(
    "/sessions",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        const pageSize = Math.min(
          100,
          Math.max(1, Number(req.query.limit) || 50),
        );
        const page = Math.max(1, Number(req.query.page) || 1);
        // Optional search over the person's address and name.
        const search = String(req.query.q ?? "").trim().slice(0, 200);

        const [{ rows: sessions }, { rows: countRows }] = await Promise.all([
          // The account and email come from idp_users (the source of truth), joined on
          // the session's accountId: oidc-provider's Session payload carries neither an
          // email nor anything but the bare id. An INNER JOIN also drops anonymous
          // sessions (a browser that reached /authorize but never signed in), so the
          // list, its count and the dashboard's count agree. The platform administrator
          // is never listed.
          pool.query(
            `SELECT
             a.id, a.kind, u.id::text AS account_id, u.email,
             nullif(btrim(concat_ws(' ', u.given_name, u.family_name)), '') AS name,
             a.created_at, a.expires_at,
             nullif(ev.ip, '') AS ip, nullif(ev.user_agent, '') AS user_agent,
             -- The applications this single sign-on session has been used to open (oidc-provider records one entry per client).
             CASE WHEN jsonb_typeof(a.payload->'authorizations') = 'object'
                  THEN (SELECT coalesce(array_agg(k ORDER BY k), '{}') FROM jsonb_object_keys(a.payload->'authorizations') k)
                  ELSE '{}' END AS clients
           FROM oidc_artifacts a
           JOIN idp_users u ON u.id::text = a.payload->>'accountId'
           -- The session payload carries no address, so it is taken from the successful
           -- sign-in record that created the session: the latest one for this account
           -- from 15 minutes before to 1 minute after the session's own login time (the
           -- record is written at the password step, the session at the end of the
           -- two-factor / forced password-change steps). NULL when no record matches
           -- (older than the 90-day retention, or signed in without a recorded event).
           LEFT JOIN LATERAL (
             SELECT e.ip, e.user_agent FROM idp_login_events e
              WHERE e.success = TRUE AND e.email = lower(u.email)
                AND (a.payload->>'loginTs') ~ '^[0-9]{1,12}$'
                AND e.created_at BETWEEN to_timestamp((a.payload->>'loginTs')::bigint) - INTERVAL '15 minutes'
                                     AND to_timestamp((a.payload->>'loginTs')::bigint) + INTERVAL '1 minute'
              ORDER BY e.created_at DESC LIMIT 1
           ) ev ON TRUE
           WHERE a.kind = 'Session' AND (a.expires_at IS NULL OR a.expires_at > NOW())
             AND NOT u.is_platform_admin
             AND ($3::text = '' OR u.email ILIKE '%' || $3 || '%' OR concat_ws(' ', u.given_name, u.family_name) ILIKE '%' || $3 || '%')
           ORDER BY a.created_at DESC
           LIMIT $1 OFFSET $2`,
            [pageSize, (page - 1) * pageSize, search],
          ),
          pool.query<{ count: string }>(
            `SELECT COUNT(*) FROM oidc_artifacts a
               JOIN idp_users u ON u.id::text = a.payload->>'accountId'
              WHERE a.kind = 'Session' AND (a.expires_at IS NULL OR a.expires_at > NOW())
                AND NOT u.is_platform_admin
                AND ($1::text = '' OR u.email ILIKE '%' || $1 || '%' OR concat_ws(' ', u.given_name, u.family_name) ILIKE '%' || $1 || '%')`,
            [search],
          ),
        ]);
        const total = Number(countRows[0].count);

        sendOk(res, {
          sessions,
          filters: { q: search },
          pagination: {
            page,
            pageSize,
            total,
            totalPages: Math.max(1, Math.ceil(total / pageSize)),
          },
          adminEmail: session.email,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/logins
   * Sign-in history with pagination and filters: filter (all, success, failed), q (email or address), reason (a reason code),
   * from and to (YYYY-MM-DD, server time, both ends inclusive). Unrecognised values are ignored rather than an error, like the Users
   * filters. The same filters drive the CSV export (activity.router.ts).
   */
  router.get(
    "/logins",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        const PAGE_SIZE = 50;
        const page = Math.max(1, Number(req.query.page) || 1);
        const filter = String(req.query.filter ?? "");
        const successFilter =
          filter === "success" ? true : filter === "failed" ? false : null;
        const from = parseIsoDate(req.query.from);
        const to = parseIsoDate(req.query.to);
        const q = String(req.query.q ?? "").trim().slice(0, 200);
        const reason = String(req.query.reason ?? "").trim().slice(0, 40);

        const f = buildLoginFilter({ success: successFilter, q, reason, from, to });
        const [{ rows: logins }, { rows: countRows }, { rows: reasonRows }] = await Promise.all([
          pool.query(
            `SELECT e.id, e.email, u.id::text AS account_id, e.success, e.reason, e.ip, e.user_agent, e.created_at
           FROM idp_login_events e
           LEFT JOIN idp_users u ON lower(u.email) = e.email
           ${f.where}
           ORDER BY e.id DESC
           LIMIT $${f.params.length + 1} OFFSET $${f.params.length + 2}`,
            [...f.params, PAGE_SIZE, (page - 1) * PAGE_SIZE],
          ),
          pool.query<{ count: string }>(
            `SELECT COUNT(*) FROM idp_login_events e
               LEFT JOIN idp_users u ON lower(u.email) = e.email
              ${f.where}`,
            f.params,
          ),
          // Which reasons exist in the log, for the drop-down (only what is actually there).
          pool.query<{ reason: string }>(
            `SELECT DISTINCT e.reason FROM idp_login_events e
               LEFT JOIN idp_users u ON lower(u.email) = e.email
              WHERE e.reason <> '' AND (u.id IS NULL OR NOT u.is_platform_admin) ORDER BY e.reason`,
          ),
        ]);

        const total = Number(countRows[0].count);

        sendOk(res, {
          logins,
          reasons: reasonRows.map((r) => r.reason),
          pagination: {
            page,
            pageSize: PAGE_SIZE,
            total,
            totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
          },
          retentionDays: loginEventRetentionDays(),
          filters: { filter: successFilter === null ? "all" : filter, from: from ?? "", to: to ?? "", q, reason },
          adminEmail: session.email,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/keys
   * List signing keys
   */
  router.get(
    "/keys",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        // The whole Signing keys page, not only Rotate/Withdraw, belongs to the platform
        // administrator: key status (which key is live, which retired one is still published)
        // is what an attacker would want to time an attack on, and a console administrator
        // has no action to take on it. (The public JWKS document itself is unaffected.)
        const canManage = await isPlatformAdminSession(session);
        if (!canManage) {
          sendError(res, 403, "ERR-PLATFORM-ADMIN-ONLY", "Signing keys are visible to the platform administrator only.");
          return;
        }
        const keys = await listSigningKeys();

        sendOk(res, {
          keys: keys.map((k) => ({
            kid: k.kid,
            isActive: k.is_active,
            createdAt: k.created_at,
            retiredAt: k.retired_at,
            // Retired is not the same as gone: a rotated-out key stays in the
            // JWKS for the overlap window so tokens signed just before the
            // rotation keep verifying. Admins need to see which it is.
            published: k.published,
          })),
          // Rotating or withdrawing a signing key is reserved to the platform administrator.
          canManage,
          adminEmail: session.email,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/audit
   * The audit trail, newest first, with pagination and filters: q (actor, target or action), action (exact, or a family ending in a
   * dot), actor, from and to (YYYY-MM-DD). Anything unrecognised is ignored, like the Users filters. `actions` lists what the trail
   * actually contains, for the drop-down.
   */
  router.get(
    "/audit",
    async (req: Request, res: Response, next: NextFunction) => {
      try {
        const session = (req as any).adminSession as PortalSession;
        const pageSize = Math.min(
          100,
          Math.max(1, Number(req.query.limit) || 50),
        );
        const page = Math.max(1, Number(req.query.page) || 1);
        const filter = {
          q: String(req.query.q ?? "").trim().slice(0, 200),
          action: String(req.query.action ?? "").trim().slice(0, 80),
          actor: String(req.query.actor ?? "").trim().slice(0, 200),
          from: parseIsoDate(req.query.from),
          to: parseIsoDate(req.query.to),
        };

        const [entries, total, actions] = await Promise.all([
          listAudit(filter, pageSize, (page - 1) * pageSize),
          countAudit(filter),
          distinctAuditActions(),
        ]);

        sendOk(res, {
          entries,
          actions,
          filters: { ...filter, from: filter.from ?? "", to: filter.to ?? "" },
          pagination: {
            limit: pageSize,
            page,
            pageSize,
            total,
            totalPages: Math.max(1, Math.ceil(total / pageSize)),
          },
          adminEmail: session.email,
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/audit/verify
   * Recompute the whole idp_admin_audit HMAC chain and report whether it holds.
   *
   * This existed only on the legacy EJS console (`admin/access.ts`'s
   * GET /admin/audit/verify), which is mounted on the backend's own port and
   * is not reachable through Apache in production — so the React console,
   * the only admin surface anyone actually uses, could display audit rows but
   * had no way to say whether they were still trustworthy. An audit log whose
   * tamper-evidence can't be checked is decoration.
   *
   * GET rather than POST, and no CSRF: it is read-only and side-effect-free.
   * verifyAuditChain() pages through the table in bounded batches, so this is
   * safe to call on a large table without pinning a pool connection.
   */
  router.get(
    "/audit/verify",
    async (_req: Request, res: Response, next: NextFunction) => {
      try {
        // Refreshes what the health check and System page report, then answers. `pin` (what an acknowledgement is bound to) stays server-side.
        const chain = await runAuditChainCheck();
        const session = (_req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
        res.set("cache-control", "no-store");
        sendOk(res, {
          chain: { ...chain, breaks: chain.breaks.map(({ pin: _pin, ...b }) => b) },
          // Only the platform administrator may acknowledge a break; the page offers the button to nobody else.
          viewerIsPlatformAdmin: await isPlatformAdminSession(session),
          minReasonLength: MIN_ACK_REASON_LENGTH,
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/role-catalog
   * Get available roles for DMS/GMS
   */
  router.get(
    "/role-catalog",
    async (_req: Request, res: Response, next: NextFunction) => {
      try {
        const [dmsRoles, gmsRoles, gmsOfficeScopedRoles] = await Promise.all([
          listDmsRoleNames(),
          listGmsRoleNames(),
          listGmsOfficeScopedRoleNames(),
        ]);

        sendOk(res, {
          dmsRoles,
          gmsRoles,
          gmsOfficeScopedRoles,
          dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
          // What the create-user form's inputs stop at. The server enforces the same numbers (admin/user-input.ts and the
          // database CHECKs), so the form reads them here instead of carrying its own copy.
          limits: {
            email: USER_LIMITS.email,
            name: USER_LIMITS.name,
            passwordMinLength: getNumber("password.minLength"),
            passwordMaxLength: PASSWORD_MAX_LENGTH,
          },
          // The user-new form's only GET before its POST /users — issue the
          // create-user CSRF token here rather than adding a dedicated endpoint.
          csrf: issueAdminCsrf(res),
        });
      } catch (err) {
        next(err);
      }
    },
  );

  /** GET /api/v1/admin/dms-departments */
  router.get(
    "/dms-departments",
    async (_req: Request, res: Response, next: NextFunction) => {
      try {
        const result = await listDmsDepartmentsForAdmin();
        if (result.error) {
          sendError(res, 503, "ERR-DMS-DEPARTMENTS", result.error);
          return;
        }
        sendOk(res, { departments: result.departments });
      } catch (err) {
        next(err);
      }
    },
  );

  /**
   * GET /api/v1/admin/offices
   * Get GMS offices list
   */
  router.get(
    "/offices",
    async (_req: Request, res: Response, next: NextFunction) => {
      try {
        if (!IDP_CONFIG.gms.internalApiKey) {
          sendError(
            res,
            503,
            "ERR-GMS-NOT-CONFIGURED",
            "GMS internal API key not configured",
          );
          return;
        }

        try {
          const offices = await listGmsOffices(rid(res));
          sendOk(res, { offices });
        } catch (err) {
          const message =
            err instanceof GmsInternalApiError
              ? err.message
              : "Could not reach GMS internal API";
          sendError(res, 503, "ERR-GMS-UNAVAILABLE", message);
        }
      } catch (err) {
        next(err);
      }
    },
  );

  return router;
}
