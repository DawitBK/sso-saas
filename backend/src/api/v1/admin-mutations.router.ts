/**
 * Admin Console Mutation API endpoints for the Next.js frontend.
 * 
 * Provides POST/PUT/DELETE operations for:
 * - Creating/updating/deleting users
 * - Managing group memberships
 * - Managing roles and permissions
 * - Revoking sessions
 * - Managing signing keys
 */

import express, { Router, type Request, type Response, type NextFunction } from 'express';
import { sendOk, sendError } from './platform.router.js';
import { getPortalSession, type PortalSession } from '../../portal/session.js';
import { IDP_CONFIG } from '../../config.js';
import { pool } from '../../db/pool.js';
import { revokeAllSessions } from '../../auth/revoke.js';
import { disableTotp } from '../../auth/local-users.js';
import { writeAudit } from '../../admin/audit.js';
import { generateSigningKey, retireSigningKey, reloadProviderKeys } from '../../jwks.js';
import { validateAdminApiCsrf } from './admin.router.js';
import type Provider from 'oidc-provider';

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

    // Attach session to request
    (req as any).adminSession = session;
    next();
  } catch (err) {
    next(err);
  }
}

export function adminMutationsRouter(provider: Provider): Router {
  const router = Router();
  
  // Apply admin authentication and JSON body parsing to all routes
  router.use(express.json({ limit: '1mb' }));
  router.use(requireAdmin);

  /**
   * PUT /api/v1/admin/users/:id
   * Update user details
   */
  router.put('/users/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      const userId = String(req.params.id);
      const { given_name, family_name, is_active } = req.body;

      const { rows } = await pool.query<{ email: string; is_active: boolean }>(
        `UPDATE idp_users
         SET given_name = COALESCE($1, given_name),
             family_name = COALESCE($2, family_name),
             is_active = COALESCE($3, is_active),
             updated_at = NOW()
         WHERE id = $4
         RETURNING email, is_active`,
        [given_name, family_name, is_active, userId],
      );

      if (rows.length === 0) {
        sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found');
        return;
      }

      const email = rows[0].email;

      // Deactivating via this endpoint must take effect immediately, same as
      // POST /users/:id/toggle-active (admin.router.ts) — revoke every live
      // session and record the same dedicated audit action it uses, instead of
      // the generic user.update below, so a disable is never invisible to
      // /admin/audit and never leaves an old session alive until next login.
      if (is_active === false) {
        const revoked = await revokeAllSessions(userId, email);
        await writeAudit(req, session.email, 'user.disable', email, {
          userId,
          changes: { given_name, family_name, is_active },
          revoked,
        });
      } else {
        await writeAudit(req, session.email, 'user.update', email, {
          userId,
          changes: { given_name, family_name, is_active },
        });
      }

      sendOk(res, { success: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/users/:id/disable-mfa
   * Disable two-factor authentication for user
   */
  router.post('/users/:id/disable-mfa', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      const userId = String(req.params.id);
      const { rows } = await pool.query<{ email: string }>(
        'SELECT email FROM idp_users WHERE id = $1',
        [userId]
      );

      if (rows.length === 0) {
        sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found');
        return;
      }

      await disableTotp(userId);
      await writeAudit(req, session.email, 'user.mfa_disable', rows[0].email, { 
        userId,
        byAdmin: true 
      });

      sendOk(res, { success: true });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/sessions/revoke
   * Revoke a session
   */
  router.post('/sessions/revoke', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      const { session_id } = req.body;

      if (!session_id) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', 'Session ID is required');
        return;
      }

      // Platform audit finding 4.5: this used to be a bare DELETE of just the
      // one Session row, leaving that account's AccessToken/RefreshToken/
      // Grant rows (and any GMS bridge session) untouched — a still-valid
      // refresh token could keep renewing this "revoked" session for a full
      // day or more. Look the account up first (non-destructively), then
      // reuse the same account-wide revokeAllSessions the admin console's
      // "sign out everywhere" button already calls — there's no narrower
      // per-session revoke primitive in this codebase, tokens/grants are
      // only tracked per-account.
      const { rows } = await pool.query<{ account_id: string | null; email: string | null }>(
        `SELECT payload->>'accountId' AS account_id, u.email
         FROM oidc_artifacts a LEFT JOIN idp_users u ON u.id::text = a.payload->>'accountId'
         WHERE a.kind = 'Session' AND a.id = $1`,
        [session_id]
      );

      let revoked: Awaited<ReturnType<typeof revokeAllSessions>> | null = null;
      if (rows[0]?.account_id && rows[0]?.email) {
        revoked = await revokeAllSessions(rows[0].account_id, rows[0].email);
      } else {
        await pool.query(`DELETE FROM oidc_artifacts WHERE kind = 'Session' AND id = $1`, [session_id]);
      }

      if (rows.length > 0) {
        await writeAudit(req, session.email, 'session.revoke', rows[0].email || rows[0].account_id || String(session_id), {
          sessionId: session_id,
          revoked,
        });
      }

      sendOk(res, { success: true, revoked: rows.length > 0 });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/keys/generate
   * Generate a new signing key
   */
  router.post('/keys/generate', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      const jwk = await generateSigningKey();
      await reloadProviderKeys(provider);

      await writeAudit(req, session.email, 'signing_key.generate', 'system', { 
        kid: jwk.kid 
      });

      sendOk(res, { kid: jwk.kid }, 201);
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /api/v1/admin/keys/:kid/retire
   * Retire a signing key
   */
  router.post('/keys/:kid/retire', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      const kid = String(req.params.kid);
      const result = await retireSigningKey(kid);

      if (!result.ok) {
        sendError(res, 400, 'ERR-CANNOT-RETIRE-KEY', result.error || 'Cannot retire key');
        return;
      }

      await reloadProviderKeys(provider);

      await writeAudit(req, session.email, 'signing_key.retire', 'system', { 
        kid 
      });

      sendOk(res, { success: true });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
