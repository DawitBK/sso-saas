import { Router, type Request, type Response } from 'express';
import { pool } from '../../db/pool.js';
import { IDP_CONFIG } from '../../config.js';

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

  router.get('/health/ready', async (_req: Request, res: Response) => {
    try {
      await pool.query('SELECT 1');
      sendOk(res, { status: 'ready', dependencies: { database: 'ok' } });
    } catch (err) {
      sendError(res, 503, 'ERR-DEPENDENCY-UNAVAILABLE', 'The SSO database is unavailable.', [
        { field: 'database', message: (err as Error).message },
      ]);
    }
  });

  router.get('/metrics', async (_req: Request, res: Response) => {
    try {
      const { rows } = await pool.query<Record<string, string>>(
        `SELECT
           (SELECT COUNT(*) FROM idp_users) AS users_total,
           (SELECT COUNT(*) FROM idp_users WHERE is_active) AS users_active,
           (SELECT COUNT(*) FROM idp_users WHERE totp_enabled) AS users_mfa_enrolled,
           (SELECT COUNT(*) FROM oidc_artifacts WHERE kind = 'Session' AND payload->>'accountId' IS NOT NULL AND (expires_at IS NULL OR expires_at > NOW())) AS sessions_sso_active,
           (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'portal' AND expires_at > NOW()) AS sessions_portal_active,
           (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'gateway' AND expires_at > NOW()) AS sessions_gateway_active,
           (SELECT COUNT(*) FROM idp_login_events WHERE created_at > NOW() - INTERVAL '1 hour') AS logins_attempted_1h,
           (SELECT COUNT(*) FROM idp_login_events WHERE success = FALSE AND created_at > NOW() - INTERVAL '1 hour') AS logins_failed_1h,
           (SELECT COUNT(*) FROM idp_signing_keys WHERE is_active) AS signing_keys_active`,
      );
      const metrics = Object.fromEntries(Object.entries(rows[0] ?? {}).map(([key, value]) => [key, Number(value)]));
      res.set('cache-control', 'no-store');
      sendOk(res, metrics);
    } catch (err) {
      sendError(res, 503, 'ERR-DEPENDENCY-UNAVAILABLE', 'SSO metrics are temporarily unavailable.', [
        { field: 'database', message: (err as Error).message },
      ]);
    }
  });

  return router;
}

