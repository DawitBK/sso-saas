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

import express, { Router, type Request, type Response, type NextFunction } from 'express';
import crypto from 'node:crypto';
import { sendOk, sendError } from './platform.router.js';
import { getPortalSession, type PortalSession } from '../../portal/session.js';
import { IDP_CONFIG } from '../../config.js';
import { pool } from '../../db/pool.js';
import {
  listDmsRoleNames,
  listGmsRoleNames,
  listGmsOfficeScopedRoleNames,
} from '../../admin/client-roles.js';
import { listGmsOffices, GmsInternalApiError } from '../../admin/gms-internal-client.js';
import {
  liveDmsStatus,
  liveGmsStatus,
  getAccess,
  resolveDmsPermissions,
  allGroupDns,
  listOffices,
  roleCatalog,
  addUserToGroup,
  removeUserFromGroup,
  addableGroupDns,
  isPersonalGroupDn,
  personalGroupDn,
  applyAccess,
  APPS,
} from '../../admin/router.js';
import { listSigningKeys } from '../../jwks.js';
import { recentAudit, writeAudit } from '../../admin/audit.js';
import { revokeAllSessions } from '../../auth/revoke.js';
import { hashPassword } from '../../auth/password.js';
import { disableTotp } from '../../auth/local-users.js';
import {
  listDmsRoles,
  getDmsRolePermissions,
  putDmsRolePermissions,
  putDmsRoleMapping,
  DmsInternalApiError,
} from '../../admin/dms-internal-client.js';
import { ALL_PERMISSIONS, groupedPermissions } from '../../admin/dms-permissions.js';

/** Extract all cookie values for a given name */
function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) {
      out.push(decodeURIComponent(part.slice(i + 1).trim()));
    }
  }
  return out;
}

/** Find active portal session from request */
async function getSessionFromRequest(req: Request): Promise<PortalSession | null> {
  for (const v of cookieValues(req, 'idp_portal')) {
    const session = await getPortalSession(v);
    if (session) return session;
  }
  return null;
}

/** Middleware: require admin group membership */
async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const session = await getSessionFromRequest(req);
    
    if (!session) {
      sendError(res, 401, 'ERR-NOT-AUTHENTICATED', 'Authentication required');
      return;
    }

    if (!session.groups.includes(IDP_CONFIG.adminGroup)) {
      sendError(res, 403, 'ERR-FORBIDDEN', 'Admin access required');
      return;
    }

    // Attach session to request for downstream handlers
    (req as any).adminSession = session;
    
    // Issue logout CSRF token
    const logoutToken = crypto.randomBytes(24).toString('hex');
    // Prefixed with publicBasePath — see the matching note in admin/csrf.ts.
    res.cookie('idp_portal_csrf', logoutToken, {
      httpOnly: true,
      sameSite: 'lax',
      secure: IDP_CONFIG.isProd,
      path: `${IDP_CONFIG.publicBasePath}/portal`
    });
    
    next();
  } catch (err) {
    next(err);
  }
}

// Distinct cookie name from the EJS console's own idp_admin_csrf (admin/csrf.ts,
// Path=/admin) — this API is mounted at /api/v1/admin, a sibling path that
// would never receive a Path=/admin cookie from the browser (see the
// cookie-path-scoping writeup in app/(auth)/interaction/[uid]/actions.ts on
// the frontend side; same class of bug, fixed here by giving this API's CSRF
// cookie its own matching path instead of reusing the EJS one's).
export const ADMIN_API_CSRF_COOKIE = 'idp_admin_api_csrf';

/** Issue CSRF token for the Next.js admin console's JSON mutations. */
function issueAdminCsrf(res: Response): string {
  const token = crypto.randomBytes(24).toString('hex');
  // Prefixed with publicBasePath — see the matching note in admin/csrf.ts.
  res.cookie(ADMIN_API_CSRF_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IDP_CONFIG.isProd,
    path: `${IDP_CONFIG.publicBasePath}/api/v1/admin`,
  });
  return token;
}

/** Double-submit check for the cookie above against the JSON body's `csrf` field. */
export function validateAdminApiCsrf(req: Request): boolean {
  const cookie = cookieValues(req, ADMIN_API_CSRF_COOKIE)[0];
  const submitted = (req.body?.csrf as string) ?? '';
  if (!cookie || !submitted || cookie.length !== submitted.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(submitted));
}

export function adminApiRouter(): Router {
  const router = Router();
  
  // Apply admin authentication to all routes
  router.use(requireAdmin);

  /**
   * GET /api/v1/admin/stats
   * Dashboard statistics
   */
  router.get('/stats', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      
      const [
        { rows: userCountRows }, 
        groupList, 
        { rows: statRows }, 
        { rows: alertRows }
      ] = await Promise.all([
        pool.query<{ count: string }>('SELECT COUNT(*) FROM idp_users'),
        allGroupDns(),
        pool.query<{ sso: string; portal: string; fails: string; audits: string }>(
          `SELECT
             (SELECT COUNT(*) FROM oidc_artifacts WHERE kind = 'Session' AND payload->>'accountId' IS NOT NULL AND (expires_at IS NULL OR expires_at > NOW())) AS sso,
             (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'portal' AND expires_at > NOW()) AS portal,
             (SELECT COUNT(*) FROM idp_login_events WHERE success = FALSE AND created_at > NOW() - INTERVAL '24 hours') AS fails,
             (SELECT COUNT(*) FROM idp_admin_audit WHERE created_at > NOW() - INTERVAL '7 days') AS audits`,
        ),
        pool.query<{ email: string; failures: string }>(
          `SELECT email, COUNT(*) AS failures FROM idp_login_events
           WHERE success = FALSE AND created_at > NOW() - INTERVAL '15 minutes'
           GROUP BY email HAVING COUNT(*) >= 5 ORDER BY failures DESC LIMIT 5`,
        ),
      ]);

      sendOk(res, {
        adminEmail: session.email,
        userCount: parseInt(userCountRows[0].count),
        groupCount: groupList.length,
        dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
        stats: {
          sso: parseInt(statRows[0].sso),
          portal: parseInt(statRows[0].portal),
          fails: parseInt(statRows[0].fails),
          audits: parseInt(statRows[0].audits),
        },
        alerts: alertRows.map(row => ({
          email: row.email,
          failures: parseInt(row.failures),
        })),
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/users
   * List users with pagination and search
   */
  router.get('/users', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const q = String(req.query.q ?? '').trim();
      const PAGE_SIZE = 20;
      const page = Math.max(1, Number(req.query.page) || 1);

      const [{ rows: users }, { rows: countRows }] = await Promise.all([
        pool.query(
          `SELECT u.id, u.email, u.given_name, u.family_name, u.is_active, u.source, u.last_login_at,
                  (SELECT COUNT(*) FROM idp_user_groups g WHERE g.user_id = u.id) AS group_count
           FROM idp_users u
           WHERE ($1 = '' OR u.email ILIKE '%' || $1 || '%')
           ORDER BY u.email
           LIMIT $2 OFFSET $3`,
          [q, PAGE_SIZE, (page - 1) * PAGE_SIZE],
        ),
        pool.query<{ count: string }>(
          `SELECT COUNT(*) FROM idp_users u WHERE ($1 = '' OR u.email ILIKE '%' || $1 || '%')`,
          [q],
        ),
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
        query: q,
        adminEmail: session.email,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/users/:id
   * Get detailed user information
   */
  router.get('/users/:id', async (req: Request, res: Response, next: NextFunction) => {
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
        sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found');
        return;
      }

      const personalDn = personalGroupDn(user.id);
      const [{ rows: groups }, { rows: history }, knownGroups, access, officesResult, liveGms, catalog] = await Promise.all([
        pool.query<{ group_dn: string }>(
          'SELECT group_dn FROM idp_user_groups WHERE user_id = $1 ORDER BY group_dn',
          [user.id]
        ),
        pool.query(
          `SELECT actor_email, action, detail, created_at FROM idp_admin_audit
           WHERE target = $1 OR detail->>'userId' = $2
           ORDER BY id DESC LIMIT 20`,
          [user.email, user.id],
        ),
        allGroupDns(),
        getAccess(personalDn, user.email),
        listOffices(),
        liveGmsStatus(user.email),
        roleCatalog(),
      ]);

      const isAdmin = groups.some((g) => g.group_dn === IDP_CONFIG.adminGroup);
      const liveDms = await liveDmsStatus(user.email);

      let dmsPermissions: Awaited<ReturnType<typeof resolveDmsPermissions>> | null = null;
      let dmsPermissionsError: string | null = null;
      if (access.dmsRole && liveDms.exists && liveDms.id) {
        try {
          dmsPermissions = await resolveDmsPermissions(access.dmsRole, liveDms.id);
        } catch (err) {
          dmsPermissionsError = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
        }
      }

      sendOk(res, {
        user,
        groups: groups.map((g) => g.group_dn).filter((dn) => dn !== personalDn),
        knownGroups: [...new Set([...knownGroups, IDP_CONFIG.adminGroup])].filter((dn) => !isPersonalGroupDn(dn)).sort(),
        isAdmin,
        liveDms,
        liveGms,
        access,
        offices: officesResult.offices,
        officesError: officesResult.error,
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
        adminEmail: session.email,
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users
   * Create a new local user
   */
  router.post('/users', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const catalog = await roleCatalog();
      const email = String(req.body.email ?? '').trim().toLowerCase();
      const givenName = String(req.body.given_name ?? '').trim();
      const familyName = String(req.body.family_name ?? '').trim();
      const password = String(req.body.password ?? '');
      const dmsRole = catalog.dmsRoles.includes(String(req.body.dms_role ?? '')) ? String(req.body.dms_role) : '';
      const gmsRole = catalog.gmsRoles.includes(String(req.body.gms_role ?? '')) ? String(req.body.gms_role) : '';
      const officeId = req.body.office_id ? Number(req.body.office_id) : null;

      if (!email || !password || password.length < 8) {
        sendError(res, 400, 'ERR-INVALID-INPUT', 'Email and an 8+ character password are required.');
        return;
      }
      if (catalog.gmsOfficeScopedRoles.includes(gmsRole) && !officeId) {
        sendError(res, 400, 'ERR-OFFICE-REQUIRED', `GMS role "${gmsRole}" requires an office — pick one.`);
        return;
      }

      const pwd = await hashPassword(password);
      let userId: string;
      try {
        const { rows } = await pool.query<{ id: string }>(
          `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active)
           VALUES ($1, TRUE, $2, $3, $4, 'local', TRUE)
           RETURNING id`,
          [email, givenName, familyName, pwd],
        );
        userId = rows[0].id;
      } catch (err: unknown) {
        if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === '23505') {
          sendError(res, 409, 'ERR-EMAIL-EXISTS', 'A user with that email already exists.');
          return;
        }
        throw err;
      }

      if (dmsRole || gmsRole) {
        await applyAccess(userId, email, personalGroupDn(userId), dmsRole, gmsRole, officeId, session.email, req);
      }
      await writeAudit(req, session.email, 'user.create', email, { userId, dmsRole, gmsRole, officeId });
      sendOk(res, { id: userId });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/access
   */
  router.post('/users/:id/access', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      if (userId === session.accountId) {
        sendError(res, 403, 'ERR-SELF-SERVICE', 'You cannot change your own DMS/GMS access — ask another admin.');
        return;
      }
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found'); return; }

      const catalog = await roleCatalog();
      const dmsRole = catalog.dmsRoles.includes(String(req.body.dms_role ?? '')) ? String(req.body.dms_role) : '';
      const gmsRole = catalog.gmsRoles.includes(String(req.body.gms_role ?? '')) ? String(req.body.gms_role) : '';
      const officeId = req.body.office_id ? Number(req.body.office_id) : null;

      if (catalog.gmsOfficeScopedRoles.includes(gmsRole) && !officeId) {
        sendError(res, 400, 'ERR-OFFICE-REQUIRED', `GMS role "${gmsRole}" requires an office to be selected.`);
        return;
      }

      await applyAccess(userId, rows[0].email, personalGroupDn(userId), dmsRole, gmsRole, officeId, session.email, req);
      await writeAudit(req, session.email, 'user.access', rows[0].email, { userId, dmsRole, gmsRole, officeId });

      const wantsAdmin = req.body.is_admin === true || req.body.is_admin === 'on' || req.body.is_admin === 'true';
      const { rows: adminMembership } = await pool.query(
        'SELECT 1 FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2',
        [userId, IDP_CONFIG.adminGroup],
      );
      const isCurrentlyAdmin = adminMembership.length > 0;
      if (wantsAdmin && !isCurrentlyAdmin) {
        await addUserToGroup(userId, rows[0].email, IDP_CONFIG.adminGroup, session.email, req);
      } else if (!wantsAdmin && isCurrentlyAdmin) {
        await removeUserFromGroup(userId, rows[0].email, IDP_CONFIG.adminGroup, session.email, req);
      }

      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/dms-permissions
   */
  router.post('/users/:id/dms-permissions', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      if (userId === session.accountId) {
        sendError(res, 403, 'ERR-SELF-SERVICE', 'You cannot change your own DMS permissions — ask another admin.');
        return;
      }
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found'); return; }
      const email = rows[0].email;

      const access = await getAccess(personalGroupDn(userId), email);
      if (!access.dmsRole) {
        sendError(res, 400, 'ERR-NO-DMS-ROLE', 'This user has no DMS role — set one under Initial system access first.');
        return;
      }
      const liveDms = await liveDmsStatus(email);
      if (!liveDms.exists || !liveDms.id) {
        sendError(res, 400, 'ERR-NOT-PROVISIONED', 'This user does not exist in DMS yet — permissions can only be customized after their first DMS sign-in.');
        return;
      }

      let state: Awaited<ReturnType<typeof resolveDmsPermissions>>;
      try {
        state = await resolveDmsPermissions(access.dmsRole, liveDms.id);
      } catch (err) {
        const message = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
        sendError(res, err instanceof DmsInternalApiError ? err.status : 503, 'ERR-DMS', message);
        return;
      }

      const validPermissions = new Set(ALL_PERMISSIONS);
      const checked = new Set(
        ([] as string[]).concat(req.body.permissions ?? []).filter((p) => validPermissions.has(p)),
      );
      const roleDefaults = new Set(state.roleDefaults);
      const grants = [...checked].filter((p) => !roleDefaults.has(p));
      const revokes = [...roleDefaults].filter((p) => !checked.has(p));

      try {
        const { putDmsUserOverrides } = await import('../../admin/dms-internal-client.js');
        const overrides = await putDmsUserOverrides(IDP_CONFIG.dmsDefaultTenant, liveDms.id, grants, revokes, session.email);
        await writeAudit(req, session.email, 'user.dms_permissions', email, {
          userId,
          dmsUserId: liveDms.id,
          dmsRole: access.dmsRole,
          grants: overrides.grants,
          revokes: overrides.revokes,
        });
      } catch (err) {
        const message = err instanceof DmsInternalApiError ? `DMS rejected the permission update: ${err.message}` : 'Could not reach the DMS internal API.';
        sendError(res, err instanceof DmsInternalApiError ? err.status : 503, 'ERR-DMS', message);
        return;
      }

      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/toggle-active
   */
  router.post('/users/:id/toggle-active', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      const { rows } = await pool.query<{ email: string; is_active: boolean }>(
        'UPDATE idp_users SET is_active = NOT is_active, updated_at = NOW() WHERE id = $1 RETURNING email, is_active',
        [userId],
      );
      if (rows[0]) {
        const revoked = rows[0].is_active ? null : await revokeAllSessions(userId, rows[0].email);
        await writeAudit(req, session.email, rows[0].is_active ? 'user.enable' : 'user.disable', rows[0].email, revoked ? { userId, revoked } : { userId });
      }
      sendOk(res, { ok: true, isActive: rows[0]?.is_active ?? null });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/reset-password
   */
  router.post('/users/:id/reset-password', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      const password = String(req.body.password ?? '');
      if (password.length < 8) {
        sendError(res, 400, 'ERR-INVALID-INPUT', 'Temporary password must be at least 8 characters.');
        return;
      }
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found'); return; }

      await pool.query(
        `UPDATE idp_users
         SET password_hash = $2, must_change_password = TRUE, failed_logins = 0, locked_until = NULL, updated_at = NOW()
         WHERE id = $1`,
        [userId, await hashPassword(password)],
      );
      const revoked = await revokeAllSessions(userId, rows[0].email);
      await writeAudit(req, session.email, 'user.password_reset', rows[0].email, { userId, revoked });
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/mfa-reset
   */
  router.post('/users/:id/mfa-reset', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found'); return; }
      await disableTotp(userId);
      await writeAudit(req, session.email, 'user.mfa_reset', rows[0].email, { userId });
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/groups — add to a shared group
   */
  router.post('/users/:id/groups', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      const groupDn = String(req.body.group_dn ?? '').trim();
      if (groupDn) {
        const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
        const allowed = await addableGroupDns();
        if (!allowed.has(groupDn)) {
          sendError(res, 400, 'ERR-UNKNOWN-GROUP', 'Not a recognized group — configure its access on the Groups page first.');
          return;
        }
        if (userId === session.accountId) {
          const groupAccess = await getAccess(groupDn);
          const grantsAppRole = Boolean(groupAccess.dmsRole || groupAccess.gmsRole);
          if (grantsAdmin || grantsAppRole) {
            sendError(res, 403, 'ERR-SELF-SERVICE', 'You cannot grant yourself elevated access — ask another admin.');
            return;
          }
        }
        const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
        if (!rows[0]) { sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found'); return; }
        await addUserToGroup(userId, rows[0].email, groupDn, session.email, req);
      }
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/groups/remove
   */
  router.post('/users/:id/groups/remove', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const userId = String(req.params.id);
      const groupDn = String(req.body.group_dn ?? '');
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found'); return; }
      await removeUserFromGroup(userId, rows[0].email, groupDn, session.email, req);
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/groups
   * List all groups
   */
  router.get('/groups', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const dns = (await allGroupDns()).filter((dn) => !isPersonalGroupDn(dn));
      const { rows: memberCounts } = await pool.query<{ group_dn: string; count: string }>(
        'SELECT group_dn, COUNT(*) AS count FROM idp_user_groups GROUP BY group_dn',
      );
      const countByDn = new Map(memberCounts.map((r) => [r.group_dn, r.count]));

      sendOk(res, {
        groups: dns.map((dn) => ({ dn, memberCount: Number(countByDn.get(dn) ?? '0') })),
        adminEmail: session.email,
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/groups/detail?dn=...
   */
  router.get('/groups/detail', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const dn = String(req.query.dn ?? '');
      if (!dn) { sendError(res, 400, 'ERR-MISSING-DN', 'dn query param is required'); return; }

      const [{ rows: members }, { rows: entRows }, accessState, catalog] = await Promise.all([
        pool.query<{ id: string; email: string }>(
          'SELECT u.id, u.email FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id WHERE g.group_dn = $1 ORDER BY u.email',
          [dn],
        ),
        pool.query<{ relying_party: string }>('SELECT relying_party FROM idp_app_entitlements WHERE group_dn = $1', [dn]),
        getAccess(dn),
        roleCatalog(),
      ]);

      sendOk(res, {
        dn,
        members,
        entitled: [...entRows.map((r) => r.relying_party)],
        apps: APPS,
        dmsRole: accessState.dmsRole,
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
  });

  /**
   * POST /api/v1/admin/groups/entitlements
   */
  router.post('/groups/entitlements', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const dn = String(req.body.dn ?? '');
      const selected = ([] as string[]).concat(req.body.rp ?? []);
      await pool.query('DELETE FROM idp_app_entitlements WHERE group_dn = $1', [dn]);
      for (const rp of selected) {
        if (APPS.some((a) => a.rp === rp)) {
          await pool.query('INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2)', [rp, dn]);
        }
      }
      await writeAudit(req, session.email, 'group.entitlements', dn, { apps: selected });
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/groups/dms-role
   */
  router.post('/groups/dms-role', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const dn = String(req.body.dn ?? '');
      const role = String(req.body.role ?? '');
      if (!IDP_CONFIG.dmsInternalApiKey) { sendError(res, 503, 'ERR-DMS-NOT-CONFIGURED', 'DMS_INTERNAL_API_KEY is not configured.'); return; }
      await putDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, role || null, session.email);
      await writeAudit(req, session.email, 'group.dms_role', dn, { role: role || null });
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/groups/gms-role
   */
  router.post('/groups/gms-role', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const dn = String(req.body.dn ?? '');
      const role = String(req.body.role ?? '');
      await pool.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [dn]);
      if (role) {
        await pool.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2) ON CONFLICT DO NOTHING', [dn, role]);
      }
      await writeAudit(req, session.email, 'group.gms_role', dn, { role: role || null });
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/dms-roles
   */
  router.get('/dms-roles', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      let roles: Awaited<ReturnType<typeof listDmsRoles>> = [];
      let error: string | null = null;
      try {
        roles = await listDmsRoles(IDP_CONFIG.dmsDefaultTenant);
      } catch (err) {
        error = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
      }
      sendOk(res, { roles, error, tenant: IDP_CONFIG.dmsDefaultTenant, adminEmail: session.email });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/dms-roles/detail?roleId=...
   */
  router.get('/dms-roles/detail', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const roleId = String(req.query.roleId ?? '');
      if (!roleId) { sendError(res, 400, 'ERR-MISSING-ROLE-ID', 'roleId query param is required'); return; }
      let roleName = '';
      let checked: string[] = [];
      let error: string | null = null;
      try {
        const result = await getDmsRolePermissions(IDP_CONFIG.dmsDefaultTenant, roleId);
        roleName = result.roleName;
        checked = result.permissions;
      } catch (err) {
        error = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
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
  });

  /**
   * POST /api/v1/admin/dms-roles/detail
   */
  router.post('/dms-roles/detail', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) { sendError(res, 400, 'ERR-CSRF', 'Invalid form submission — please retry.'); return; }
      const session = (req as any).adminSession as PortalSession;
      const roleId = String(req.body.roleId ?? '');
      if (!roleId) { sendError(res, 400, 'ERR-MISSING-ROLE-ID', 'roleId is required'); return; }
      const validPermissions = new Set(ALL_PERMISSIONS);
      const selected = ([] as string[]).concat(req.body.permissions ?? []).filter((p) => validPermissions.has(p));
      try {
        await putDmsRolePermissions(IDP_CONFIG.dmsDefaultTenant, roleId, selected, session.email);
      } catch (err) {
        const message = err instanceof DmsInternalApiError ? `DMS rejected the permission update: ${err.message}` : 'Could not reach the DMS internal API.';
        sendError(res, err instanceof DmsInternalApiError ? err.status : 503, 'ERR-DMS', message);
        return;
      }
      await writeAudit(req, session.email, 'dms_role.permissions', roleId, { roleId, permissions: selected });
      sendOk(res, { ok: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/clients
   * List OAuth clients
   */
  router.get('/clients', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;

      // Registered relying parties (idp_clients), not "which clients currently
      // have an active session" — the query this replaced derived its list
      // from oidc_artifacts, which silently omitted any client with zero live
      // sessions and had none of the fields (name, redirect_uris, grant_types)
      // the frontend actually needs.
      const { rows: clients } = await pool.query(
        `SELECT client_id, name AS client_name, redirect_uris, grant_types, created_at
         FROM idp_clients
         WHERE is_active = TRUE
         ORDER BY client_id`,
      );

      sendOk(res, {
        clients,
        adminEmail: session.email,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/sessions
   * List active sessions
   */
  router.get('/sessions', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      
      const { rows: sessions } = await pool.query(
        `SELECT
           id, kind, payload->>'accountId' AS account_id,
           payload->>'email' AS email, created_at, expires_at
         FROM oidc_artifacts
         WHERE kind = 'Session' AND (expires_at IS NULL OR expires_at > NOW())
         ORDER BY created_at DESC
         LIMIT 100`,
      );

      sendOk(res, {
        sessions,
        adminEmail: session.email,
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/logins
   * Login history with pagination
   */
  router.get('/logins', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const PAGE_SIZE = 50;
      const page = Math.max(1, Number(req.query.page) || 1);
      const filter = String(req.query.filter ?? '');
      const successFilter = filter === 'success' ? true : filter === 'failed' ? false : null;

      const [{ rows: logins }, { rows: countRows }] = await Promise.all([
        pool.query(
          `SELECT id, email, success, reason, ip, user_agent, created_at
           FROM idp_login_events
           WHERE ($3::boolean IS NULL OR success = $3)
           ORDER BY id DESC
           LIMIT $1 OFFSET $2`,
          [PAGE_SIZE, (page - 1) * PAGE_SIZE, successFilter],
        ),
        pool.query<{ count: string }>(
          'SELECT COUNT(*) FROM idp_login_events WHERE ($1::boolean IS NULL OR success = $1)',
          [successFilter],
        ),
      ]);

      const total = Number(countRows[0].count);

      sendOk(res, {
        logins,
        pagination: {
          page,
          pageSize: PAGE_SIZE,
          total,
          totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
        },
        adminEmail: session.email,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/keys
   * List signing keys
   */
  router.get('/keys', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const keys = await listSigningKeys();

      sendOk(res, {
        keys: keys.map(k => ({
          kid: k.kid,
          isActive: k.is_active,
          createdAt: k.created_at,
          retiredAt: k.retired_at,
        })),
        adminEmail: session.email,
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/audit
   * Audit log with pagination
   */
  router.get('/audit', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 50));

      const entries = await recentAudit(limit);

      sendOk(res, {
        entries,
        pagination: {
          limit,
        },
        adminEmail: session.email,
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/role-catalog
   * Get available roles for DMS/GMS
   */
  router.get('/role-catalog', async (_req: Request, res: Response, next: NextFunction) => {
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
        // The user-new form's only GET before its POST /users — issue the
        // create-user CSRF token here rather than adding a dedicated endpoint.
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/admin/offices
   * Get GMS offices list
   */
  router.get('/offices', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      if (!IDP_CONFIG.gms.internalApiKey) {
        sendError(res, 503, 'ERR-GMS-NOT-CONFIGURED', 'GMS internal API key not configured');
        return;
      }

      try {
        const offices = await listGmsOffices();
        sendOk(res, { offices });
      } catch (err) {
        const message = err instanceof GmsInternalApiError 
          ? err.message 
          : 'Could not reach GMS internal API';
        sendError(res, 503, 'ERR-GMS-UNAVAILABLE', message);
      }
    } catch (err) {
      next(err);
    }
  });

  return router;
}
