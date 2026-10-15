import { Router, type Request, type Response } from 'express';
import { IDP_CONFIG } from '../../config.js';
import { logger } from '../../logging/logger.js';
import { collectPlatformMetrics, metricsAccessAllowed } from '../../ops/metrics.js';
import { PROMETHEUS_CONTENT_TYPE, collectPrometheus, wantsPrometheus } from '../../ops/prometheus.js';
import { collectReadiness, httpStatusFor, publicView } from '../../ops/readiness.js';

type ApiMeta = { requestId: string };

function meta(res: Response): ApiMeta {
  return { requestId: String(res.locals.requestId ?? '') };
}

export function sendOk<T>(res: Response, data: T, status = 200): void {
  res.status(status).json({ data, meta: meta(res) });
}

export function sendError(
  res: Response,
  status: number,
  code: string,
  message: string,
  details?: Array<{ field?: string; message: string }>,
): void {
  res.status(status).json({
    error: { code, message, ...(details?.length ? { details } : {}) },
    meta: meta(res),
  });
}

/**
 * Versioned operational API. The unversioned health and OIDC routes remain
 * available as compatibility endpoints while applications move to `/api/v1`.
 */
export function platformApiRouter(): Router {
  const router = Router();

  router.get('/health', (_req: Request, res: Response) => {
    sendOk(res, { status: 'ok', issuer: IDP_CONFIG.issuer, gmsBridge: IDP_CONFIG.gms.enabled });
  });

  // The same collector as the unversioned /health/ready (ops/readiness.ts) — they were two copies that drifted.
  // P1-20: state words only. `(err as Error).message` once went straight into this UNAUTHENTICATED body; a raw Postgres connection
  // error names the host, the database and the role.
  router.get('/health/ready', async (_req: Request, res: Response) => {
    try {
      const readiness = await collectReadiness();
      const view = publicView(readiness);
      res.set('cache-control', 'no-store');
      if (httpStatusFor(readiness) === 503) {
        sendError(res, 503, 'ERR-DEPENDENCY-UNAVAILABLE', 'SSO cannot serve sign-ins right now.');
        return;
      }
      sendOk(res, { status: view.status, dependencies: view.checks });
    } catch (err) {
      logger.error({ err, requestId: res.locals.requestId }, '[idp:health] readiness probe failed');
      sendError(res, 503, 'ERR-DEPENDENCY-UNAVAILABLE', 'SSO cannot serve sign-ins right now.');
    }
  });

  /**
   * P1-20: authenticated, and sharing one collector with main.ts's `/metrics`
   * alias instead of a second copy of the SQL. See ops/metrics.ts.
   */
  router.get('/metrics', async (req: Request, res: Response) => {
    if (!(await metricsAccessAllowed(req))) {
      sendError(res, 401, 'ERR-NOT-AUTHENTICATED', 'Authentication is required for platform metrics.');
      return;
    }
    try {
      res.set('cache-control', 'no-store');
      if (wantsPrometheus(req)) {
        res.type(PROMETHEUS_CONTENT_TYPE).send(await collectPrometheus());
        return;
      }
      sendOk(res, await collectPlatformMetrics());
    } catch (err) {
      logger.error({ err, requestId: res.locals.requestId }, '[idp:metrics] query failed');
      sendError(res, 503, 'ERR-DEPENDENCY-UNAVAILABLE', 'SSO metrics are temporarily unavailable.');
    }
  });

  return router;
}

