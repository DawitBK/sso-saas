/**
 * Inbound internal API: GMS calling INTO SSO to manage per-user role grants
 * (directive §6.3 — "GMS's own admin interfaces call SSO's role- and
 * user-management API in the background"). Gated by SSO_ROLES_API_KEY, the
 * opposite direction from the GMS_INTERNAL_API_KEY-gated bridge/gms.ts calls.
 */

import crypto from 'node:crypto';
import { Router, type NextFunction, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { getGrantedRoles, setGrantedRoles } from '../auth/client-user-roles.js';
import { revokeAllSessions } from '../auth/revoke.js';
import { parseOrSendError } from '../validation/parse.js';
import { EmailParamSchema, SetRolesBodySchema } from './gms-role-grants.schemas.js';
import { writeAudit } from './audit.js';

// The shared-secret check below is constant-time, but with no throttle an
// attacker who can reach this endpoint could still brute-force
// SSO_ROLES_API_KEY given enough attempts if it were ever short/guessable.
const gmsRolesKeyLimiter = rateLimit({ windowMs: 60_000, limit: 30, standardHeaders: true, legacyHeaders: false });

function constantTimeEquals(provided: string, expected: string): boolean {
  const providedBuffer = Buffer.from(provided);
  const expectedBuffer = Buffer.from(expected);
  return providedBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(providedBuffer, expectedBuffer);
}

function requireGmsRolesKey(req: Request, res: Response, next: NextFunction): void {
  const configured = IDP_CONFIG.gms.rolesApiKey;
  if (!configured) {
    res.status(503).json({ success: false, error: { message: 'SSO_ROLES_API_KEY is not configured' } });
    return;
  }
  const provided = req.header('x-internal-api-key');
  if (!provided || !constantTimeEquals(provided, configured)) {
    res.status(401).json({ success: false, error: { message: 'Invalid or missing internal API key' } });
    return;
  }
  next();
}

export function gmsRoleGrantsRouter(): Router {
  const router = Router();
  router.use(gmsRolesKeyLimiter);
  router.use(requireGmsRolesKey);

  router.get('/users/:email/roles', async (req: Request, res: Response) => {
    const sendError = (details: Array<{ field?: string; message: string }>) =>
      res.status(400).json({ success: false, error: { message: details[0]?.message ?? 'Invalid request', details } });

    const parsedParams = parseOrSendError(
      EmailParamSchema,
      { email: decodeURIComponent(String(req.params.email ?? '')) },
      sendError,
    );
    if (!parsedParams) return;

    const roles = await getGrantedRoles(parsedParams.data.email.toLowerCase(), 'gms');
    res.json({ success: true, data: { roles } });
  });

  router.put('/users/:email/roles', async (req: Request, res: Response) => {
    const sendError = (details: Array<{ field?: string; message: string }>) =>
      res.status(400).json({ success: false, error: { message: details[0]?.message ?? 'Invalid request', details } });

    const parsedParams = parseOrSendError(
      EmailParamSchema,
      { email: decodeURIComponent(String(req.params.email ?? '')) },
      sendError,
    );
    if (!parsedParams) return;

    const parsedBody = parseOrSendError(SetRolesBodySchema, req.body, sendError);
    if (!parsedBody) return;

    const email = parsedParams.data.email.toLowerCase();
    const grantedBy = parsedBody.data.grantedBy ?? 'gms';

    try {
      await setGrantedRoles(email, 'gms', parsedBody.data.roles, grantedBy);
    } catch (err) {
      res.status(400).json({ success: false, error: { message: (err as Error).message } });
      return;
    }

    // FIX: this write — GMS granting/replacing a user's GMS role set, the
    // highest-precedence source per client-role-claims.ts — had no audit
    // trail at all, unlike every other role/access mutation in this codebase.
    // Best-effort: the role change already succeeded above, so an audit-write
    // failure shouldn't turn into a 500 for a request GMS otherwise sees as
    // successful (same fail-open treatment other side-effect audit writes in
    // this codebase get, e.g. applyAccess's entitlement.desync write).
    await writeAudit(req, grantedBy, 'user.gms_roles.set', email, { roles: parsedBody.data.roles }).catch(() => {});

    // Platform audit finding 4.6: this is the highest-precedence GMS role
    // source (client-role-claims.ts checks it before AD-group mapping), but
    // unlike every other role/access mutation in this codebase it never
    // revoked existing sessions — a demotion or revocation through this
    // endpoint had zero effect on an already-active bridged GMS session
    // (bridge/gms.ts mints its own session independently at bridge time and
    // doesn't re-check this table until the next fresh bridge). Mirrors
    // addUserToGroup/removeUserFromGroup's unconditional revoke-on-change.
    // Best-effort and non-blocking: GMS already sees the role write as
    // successful, so a revoke hiccup shouldn't turn that into an error.
    const { rows: userRows } = await pool.query<{ id: string }>('SELECT id FROM idp_users WHERE email = $1', [email]);
    if (userRows[0]) {
      await revokeAllSessions(userRows[0].id, email).catch((err) => {
        writeAudit(req, grantedBy, 'user.gms_roles.revoke_failed', email, { error: (err as Error).message }).catch(() => {});
      });
    }

    res.json({ success: true, data: { roles: await getGrantedRoles(email, 'gms') } });
  });

  return router;
}
