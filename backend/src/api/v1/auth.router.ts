/**
 * Authentication API endpoints for the Next.js frontend.
 * 
 * These endpoints provide JSON responses for:
 * - Session status checks
 * - Login/logout operations
 * - Authentication state
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { sendOk, sendError } from './platform.router.js';
import { getPortalSession, type PortalSession } from '../../portal/session.js';
import { issueSecurityCsrf } from '../../portal/router.js';
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

export function authApiRouter(): Router {
  const router = Router();

  /**
   * GET /api/v1/auth/session
   * Get current authenticated user session
   */
  router.get('/session', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = await getSessionFromRequest(req);
      if (!session) {
        sendError(res, 401, 'ERR-NOT-AUTHENTICATED', 'No active session');
        return;
      }

      // Issued once authenticated, so the frontend has a fresh double-submit
      // CSRF token in hand for the one thing it needs to POST next: logout.
      const csrf = issueSecurityCsrf(res);

      const isAdmin = session.groups.includes(IDP_CONFIG.adminGroup);

      sendOk(res, {
        authenticated: true,
        csrf,
        user: {
          accountId: session.accountId,
          name: session.name || session.email,
          email: session.email,
          isAdmin,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /api/v1/auth/check
   * Quick authentication check (lighter than /session)
   */
  router.get('/check', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = await getSessionFromRequest(req);
      sendOk(res, { authenticated: !!session });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
