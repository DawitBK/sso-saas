/**
 * Portal API endpoints for the Next.js frontend.
 * 
 * Provides JSON data for the SSO portal/launcher page.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import crypto from 'node:crypto';
import { sendOk, sendError } from './platform.router.js';
import { getPortalSession, type PortalSession } from '../../portal/session.js';
import { catalog, adminTile, entitled } from '../../portal/catalog.js';
import { IDP_CONFIG } from '../../config.js';

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

/** Issue CSRF token for portal forms */
function issuePortalCsrf(res: Response): string {
  const token = crypto.randomBytes(24).toString('hex');
  // Prefixed with publicBasePath — see the matching note in admin/csrf.ts.
  res.cookie('idp_portal_csrf', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IDP_CONFIG.isProd,
    path: `${IDP_CONFIG.publicBasePath}/portal`
  });
  return token;
}

export function portalApiRouter(): Router {
  const router = Router();

  /**
   * GET /api/v1/portal
   * Get portal data: user info, entitled apps, csrf token
   */
  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = await getSessionFromRequest(req);
      
      if (!session) {
        sendError(res, 401, 'ERR-NOT-AUTHENTICATED', 'No active session');
        return;
      }

      const isAdmin = session.groups.includes(IDP_CONFIG.adminGroup);
      const allow = await entitled(session.groups);
      const apps = catalog().filter((a) => allow.has(a.rp));

      // Admins get the console as a first-class tile
      if (isAdmin) apps.push(adminTile());

      const csrf = issuePortalCsrf(res);

      sendOk(res, {
        user: {
          name: session.name || session.email,
          email: session.email,
          isAdmin,
        },
        apps,
        csrf,
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
