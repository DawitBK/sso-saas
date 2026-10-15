/**
 * Admin Console Mutation API endpoints for the Next.js frontend.
 * 
 * Provides POST/PUT operations for:
 * - Creating and updating users (P2-5: there is NO delete-user route here, and
 *   the header used to claim one. Deactivation via the update route is the
 *   supported way to retire an account — an account's `sub` is referenced by
 *   every relying party's own records, so hard-deleting it would orphan them.)
 * - Managing group memberships
 * - Managing roles and permissions
 * - Revoking sessions
 * - Managing signing keys
 */

import { selfDisableRefusal } from '../../admin/user-guards.js';
import { USER_LIMITS } from '../../admin/user-input.js';
import { guardPlatformAdminUserParam, isPlatformAdminId, isPlatformAdminSession } from '../../auth/platform-admin.js';
import express, { Router, type Request, type Response, type NextFunction } from 'express';
import { sendOk, sendError } from './platform.router.js';
import type { PortalSession } from '../../portal/session.js';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { pool } from '../../db/pool.js';
import { revokeAllSessions } from '../../auth/revoke.js';
import { writeAudit, acknowledgeChainBreak, ChainAcknowledgementError } from '../../admin/audit.js';
import { rememberAuditChainResult } from '../../ops/auditChain.js';
import { rotateSigningKey, retireSigningKey, reloadProviderKeys } from '../../jwks.js';
import { issueAdminCsrf, validateAdminApiCsrf } from './admin.router.js';
import type Provider from 'oidc-provider';

// requireAdmin (session lookup, admin-group check) now lives in
// admin/requireAdmin.ts — see SSO-F4. Unlike admin.router.ts, this router
// never issued the logout-CSRF cookie itself, so it doesn't opt in here either.
const requireAdmin = requireAdminJson(sendError);

export function adminMutationsRouter(provider: Provider): Router {
  const router = Router();
  
  // Apply admin authentication and JSON body parsing to all routes
  router.use(express.json({ limit: '1mb' }));
  router.use(requireAdmin);

  // The platform administrator does not exist for this console (auth/platform-admin.ts).
  router.param('id', guardPlatformAdminUserParam((res) => sendError(res, 404, 'ERR-USER-NOT-FOUND', 'User not found')));

  /**
   * POST /api/v1/admin/audit/chain-acknowledgements   { sequenceNumber, kind, reason, csrf }
   * Record that one break the verifier reports right now is known and harmless (see acknowledgeChainBreak). The platform administrator's
   * alone: acknowledging a break is a statement about whether the log can be trusted, and it should come from the one account that is not
   * an ordinary console administrator. The break stays listed; the acknowledgement is itself an entry in the chain.
   */
  router.post('/audit/chain-acknowledgements', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as any).adminSession as PortalSession;
      if (!(await isPlatformAdminSession(session))) {
        sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Only the platform administrator can acknowledge a break in the audit chain.');
        return;
      }
      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }
      const body = (req.body ?? {}) as { sequenceNumber?: unknown; kind?: unknown; reason?: unknown };
      let chain;
      try {
        chain = await acknowledgeChainBreak(req, session.email, {
          sequenceNumber: String(body.sequenceNumber ?? ''),
          kind: String(body.kind ?? ''),
          reason: typeof body.reason === 'string' ? body.reason : '',
        });
      } catch (err) {
        if (err instanceof ChainAcknowledgementError) {
          sendError(res, err.status, err.code, err.message);
          return;
        }
        throw err;
      }
      // Already re-verified inside acknowledgeChainBreak; remember that outcome so the health check stops reporting it at once.
      rememberAuditChainResult(chain);
      sendOk(res, { chain: { ...chain, breaks: chain.breaks.map(({ pin: _pin, ...b }) => b) }, csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

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
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', 'Invalid user id');
        return;
      }
      // Validate and normalise instead of trusting the body: a string "false" used to disable the row in SQL but skip the
      // session revoke, and the name fields were unbounded.
      const text = (v: unknown, max: number): string | null | 'bad' =>
        v === undefined || v === null ? null : typeof v === 'string' && v.trim().length <= max ? v.trim() : 'bad';
      const given_name = text(req.body.given_name, USER_LIMITS.name);
      const family_name = text(req.body.family_name, USER_LIMITS.name);
      const rawActive = req.body.is_active;
      const is_active: boolean | null =
        rawActive === undefined || rawActive === null ? null : rawActive === true || rawActive === 'true' ? true : rawActive === false || rawActive === 'false' ? false : null;
      if (given_name === 'bad' || family_name === 'bad' || (rawActive !== undefined && rawActive !== null && is_active === null)) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', `First and last name must be text of at most ${USER_LIMITS.name} characters, and is_active a boolean.`);
        return;
      }
      if (is_active === false) {
        const refusal = selfDisableRefusal(session.accountId, userId);
        if (refusal) {
          sendError(res, 403, 'ERR-SELF-SERVICE', refusal);
          return;
        }
      }

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

      // The platform administrator is invisible to every other administrator: a session of theirs answers exactly like
      // an unknown session (no oracle, and nobody can sign the owner out).
      if (rows[0]?.account_id && (await isPlatformAdminId(rows[0].account_id)) && !(await isPlatformAdminSession(session))) {
        sendOk(res, { success: true, revoked: false });
        return;
      }
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

      if (!(await isPlatformAdminSession(session))) {
        sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Only the platform administrator can manage signing keys: it is reserved above the IdP administrator group.');
        return;
      }

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      // rotateSigningKey, not generateSigningKey — see the note in jwks.ts:
      // generateSigningKey never demotes the outgoing key.
      const jwk = await rotateSigningKey();
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

      if (!(await isPlatformAdminSession(session))) {
        sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Only the platform administrator can manage signing keys: it is reserved above the IdP administrator group.');
        return;
      }

      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }

      const kid = String(req.params.kid);
      const result = await retireSigningKey(kid);

      if (!result.ok) {
        sendError(res, 409, 'ERR-CANNOT-RETIRE-KEY', result.error || 'Cannot retire key');
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
