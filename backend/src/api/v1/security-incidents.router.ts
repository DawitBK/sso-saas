/**
 * Security incidents (docs/sso/SSO-OPERATIONS.md, "Tamper detection and incident response").
 *
 *   GET /api/v1/admin/security-incidents       the recorded incidents (newest first, ?limit= &offset=), the state of the incident lock and whether the
 *                                              incident chain verifies. The platform administrator only; anyone else is answered 404, as if it did not exist.
 *   GET /api/v1/ops/chain-head                 the audit-chain head for the out-of-process watcher's anchor; HMAC-authenticated (ops/chainHead.ts).
 *
 * Read-only on purpose. A lock is cleared and an incident is closed ONLY from a terminal on the server (deploy/tamper/tamper.cjs clear): nothing here, and
 * nothing in the web console, can lift containment, because whoever caused the incident may be the one holding a web session.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { isPlatformAdminSession } from '../../auth/platform-admin.js';
import { createLimiter } from '../../infrastructure/rateLimiter.js';
import { collectChainHead, opsRequestAllowed, readOpsKey } from '../../ops/chainHead.js';
import { listIncidents, lockStatus, verifyIncidentChain } from '../../ops/incidents.js';
import type { PortalSession } from '../../portal/session.js';
import { sendError, sendOk } from './platform.router.js';

export function securityIncidentsRouter(): Router {
  const router = Router();
  router.use(requireAdminJson(sendError));
  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as Request & { adminSession?: PortalSession }).adminSession;
      if (!(await isPlatformAdminSession(session))) {
        sendError(res, 404, 'ERR-NOT-FOUND', 'Not found.');
        return;
      }
      const limit = Math.min(Math.max(Number.parseInt(String(req.query.limit ?? '100'), 10) || 100, 1), 500);
      const offset = Math.max(Number.parseInt(String(req.query.offset ?? '0'), 10) || 0, 0);
      const [list, chain] = await Promise.all([listIncidents(limit, offset), verifyIncidentChain()]);
      res.set('cache-control', 'no-store');
      sendOk(res, {
        ...list,
        lock: lockStatus(),
        chain: { valid: chain.valid, checked: chain.checked, brokenAt: chain.brokenAt ?? null, problem: chain.problem ?? null },
        clearing: 'A lock is cleared only from a terminal on the server: node deploy\tamper\tamper.cjs clear (see the operations guide). It cannot be cleared here.',
      });
    } catch (err) {
      next(err);
    }
  });
  return router;
}

export function opsWatchRouter(): Router {
  const router = Router();
  const limiter = createLimiter('ops-watch', { windowMs: 60_000, limit: 60 });
  router.get('/chain-head', limiter, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const key = readOpsKey();
      if (!key || !opsRequestAllowed(req.header('x-kg-ops'), key)) {
        // Unconfigured and unauthenticated look the same: nothing is here.
        sendError(res, 404, 'ERR-NOT-FOUND', 'Not found.');
        return;
      }
      res.set('cache-control', 'no-store');
      sendOk(res, await collectChainHead(typeof req.query.sequence === 'string' ? req.query.sequence : undefined));
    } catch (err) {
      next(err);
    }
  });
  return router;
}
