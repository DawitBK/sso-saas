/**
 * GET /api/v1/admin/system: the System page's data (ops/system.ts). Any signed-in console administrator may read it; it holds no
 * secret, only how this process and the systems around it are doing.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { collectSystem } from '../../ops/system.js';
import { sendError, sendOk } from './platform.router.js';

export function systemRouter(): Router {
  const router = Router();
  router.use(requireAdminJson(sendError));
  router.get('/', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      res.set('cache-control', 'no-store');
      sendOk(res, await collectSystem());
    } catch (err) {
      next(err);
    }
  });
  return router;
}
