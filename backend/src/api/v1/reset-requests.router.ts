/**
 * Password reset requests (auth/reset-requests.ts, migration 022).
 *
 *   POST /api/v1/auth/password-reset-request                  public: { email, note? }; ALWAYS the same answer, whether or not anything was recorded
 *   GET  /api/v1/admin/password-reset-requests                administrators: the open requests, oldest first
 *   POST /api/v1/admin/password-reset-requests/:id/dismiss    administrators: { csrf }
 *
 * Resetting the password (POST /admin/users/:id/reset-password) closes that person's open request by itself.
 */
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { writeAudit } from '../../admin/audit.js';
import { isPlatformAdminSession } from '../../auth/platform-admin.js';
import { createResetRequest, dismissResetRequest, listOpenResetRequests } from '../../auth/reset-requests.js';
import { clientIpOf } from '../../http/client-ip.js';
import { logger } from '../../logging/logger.js';
import type { PortalSession } from '../../portal/session.js';
import { issueAdminCsrf, validateAdminApiCsrf } from './admin.router.js';
import { sendError, sendOk } from './platform.router.js';

/** The one answer a person gets. It must not depend on whether the address has an account. */
export const RESET_REQUEST_ANSWER =
  'If that address belongs to an account that can ask for a reset here, the administrators have been told. They will contact you; nothing is sent by email.';

export function publicResetRequestRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '4kb' }));
  router.post('/', async (req: Request, res: Response) => {
    const body = (req.body ?? {}) as { email?: unknown; note?: unknown };
    try {
      await createResetRequest(body.email, body.note, clientIpOf(req));
    } catch (err) {
      // A database failure must not become a different answer (that would tell the asker something); it is logged and the answer stays the same.
      logger.error({ err }, '[idp:reset-request] could not record a password reset request');
    }
    res.set('cache-control', 'no-store');
    sendOk(res, { message: RESET_REQUEST_ANSWER });
  });
  return router;
}

export function resetRequestsAdminRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '16kb' }));
  router.use(requireAdminJson(sendError));

  router.get('/', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.set('cache-control', 'no-store');
      sendOk(res, { requests: await listOpenResetRequests(), csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

  router.post('/:id/dismiss', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      const by = (await isPlatformAdminSession(session)) ? 'platform' : session.email;
      const email = await dismissResetRequest(String(req.params.id), by);
      if (!email) {
        sendError(res, 404, 'ERR-REQUEST-NOT-FOUND', 'That request is not open any more.');
        return;
      }
      await writeAudit(req, session.email, 'password_reset_request.dismiss', email, {});
      sendOk(res, { ok: true, csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
