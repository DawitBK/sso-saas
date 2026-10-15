/**
 * Shared admin-group-membership gate.
 *
 * PLATFORM-VERIFICATION-AUDIT-2026-09-19 (SSO-F4): this logic — find the
 * `idp_portal` session cookie, resolve it, check `IDP_CONFIG.adminGroup`
 * membership — was independently reimplemented three times (the EJS admin
 * console, `api/v1/admin.router.ts`, `api/v1/admin-mutations.router.ts`), all
 * three currently consistent but with three call sites to keep in sync for
 * any future change to the admin-gating rule. This is the one place that
 * logic lives now; the three routers below wrap it for their own
 * response style (HTML redirect/render vs. JSON error envelope) and whether
 * they need to (re)issue the portal's logout-CSRF cookie.
 */
import { pool } from '../db/pool.js';
import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { getPortalSession, type PortalSession } from '../portal/session.js';
import { IDP_CONFIG } from '../config.js';
import { reuseOrIssueCsrf } from '../http/csrf-token.js';
import { getBool } from '../settings/store.js';

declare module 'express-serve-static-core' {
  interface Request {
    adminSession?: PortalSession;
  }
}

/** All values for a cookie name — a stale same-name cookie at another path must
 *  never shadow the live session. */
function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) out.push(decodeURIComponent(part.slice(i + 1).trim()));
  }
  return out;
}

/** Find the active portal session from the `idp_portal` cookie, if any. */
export async function getPortalSessionFromRequest(req: Request): Promise<PortalSession | null> {
  for (const v of cookieValues(req, 'idp_portal')) {
    const session = await getPortalSession(v);
    if (session) return session;
  }
  return null;
}

function issueLogoutCsrfCookie(res: Response): void {
  // Prefixed with publicBasePath: under /sso this cookie must be scoped to /sso/portal, not a bare /portal, or the browser never
  // sends it back. The same cookie the portal's Security page uses, and reused (http/csrf-token.ts) so opening the console does
  // not invalidate a Security form open in another tab.
  res.locals.logoutCsrf = reuseOrIssueCsrf(res, 'idp_portal_csrf', {
    httpOnly: true,
    sameSite: 'lax',
    secure: IDP_CONFIG.isProd,
    path: `${IDP_CONFIG.publicBasePath}/portal`,
  });
}


/**
 * The platform setting mfa.requireForAdmins (default from ADMIN_REQUIRE_MFA, false): an administrator without two-factor sign-in enrolled is refused the console
 * until they enrol one (portal > Security). A password alone should not be enough to run every system's access.
 * Off by default so enabling it is a deliberate step taken after the administrators have enrolled.
 */
async function adminMfaMissing(accountId: string): Promise<boolean> {
  if (!getBool('mfa.requireForAdmins')) return false;
  const { rows } = await pool.query<{ totp_enabled: boolean }>('SELECT totp_enabled FROM idp_users WHERE id = $1', [accountId]);
  return !rows[0]?.totp_enabled;
}
const MFA_REQUIRED_MESSAGE = 'Two-factor sign-in is required for administrators. Turn it on under Portal > Security, then come back.';

/**
 * Middleware factory for the JSON admin APIs (`api/v1/admin.router.ts`,
 * `api/v1/admin-mutations.router.ts`): unauthenticated/non-admin → JSON error
 * envelope via the given `sendError`. Pass `issueLogoutCsrf: true` only from
 * the one router that owns issuing that cookie (`admin.router.ts`, mirroring
 * its pre-refactor behavior) — the mutations router never has.
 */
export function requireAdminJson(
  sendError: (res: Response, status: number, code: string, message: string) => void,
  opts: { issueLogoutCsrf?: boolean } = {},
): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const session = await getPortalSessionFromRequest(req);
      if (!session) {
        sendError(res, 401, 'ERR-NOT-AUTHENTICATED', 'Authentication required');
        return;
      }
      if (!session.groups.includes(IDP_CONFIG.adminGroup)) {
        sendError(res, 403, 'ERR-FORBIDDEN', 'Admin access required');
        return;
      }
      if (await adminMfaMissing(session.accountId)) {
        sendError(res, 403, 'ERR-MFA-REQUIRED', MFA_REQUIRED_MESSAGE);
        return;
      }
      (req as any).adminSession = session;
      if (opts.issueLogoutCsrf) {
        issueLogoutCsrfCookie(res);
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}
