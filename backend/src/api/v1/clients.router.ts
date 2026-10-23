/**
 * Relying-party management API (admin > Clients).
 *
 *   GET  /api/v1/admin/clients                    every client with its addresses, state, scopes, usage and secret age (never the secret)
 *   GET  /api/v1/admin/clients/:clientId          one client
 *   PUT  /api/v1/admin/clients/:clientId/uris     replace the redirect and post-logout addresses            (platform administrator)
 *   POST /api/v1/admin/clients/:clientId/restore-uris   put the addresses back to the configured ones           (platform administrator)
 *   PUT  /api/v1/admin/clients/:clientId/active   switch a client on or off; off also ends what it already holds (platform administrator)
 *   POST /api/v1/admin/clients/:clientId/rotate-secret   a new secret, shown once                             (platform administrator)
 *
 * Reading belongs to every console administrator. Anything that changes who may receive a sign-in belongs to the platform
 * administrator, the same line the signing keys draw. Changes reach oidc-provider on the next request (adapters/postgres.ts).
 * The portal client is protected: the console itself signs in through it with a secret and addresses read from the environment, so
 * editing, rotating or disabling it from the console would lock every administrator out. "Restore" is its recovery path.
 *
 * `GET /:clientId/users` (who may open the application) stays in admin.router.ts and falls through to it.
 */
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { writeAudit } from '../../admin/audit.js';
import { isPlatformAdminSession } from '../../auth/platform-admin.js';
import { usersEntitledToClient } from '../../admin/access.js';
import { IDP_CONFIG } from '../../config.js';
import type { PortalSession } from '../../portal/session.js';
import { getClientDetails, isManagedClient, listClientDetails, rotateClientSecret, setClientActive, updateClientUris } from '../../oidc/client-admin.js';
import { validateClientUris } from '../../oidc/client-validation.js';
import { requireOwnerAuthorisation } from '../../owner/middleware.js';
import { issueAdminCsrf, validateAdminApiCsrf } from './admin.router.js';
import { sendError, sendOk } from './platform.router.js';

const requireAdmin = requireAdminJson(sendError);
const PROTECTED = new Set(['portal']);

const entitled = async (clientId: string): Promise<number | null> => {
  if (clientId === 'portal') return null;
  try {
    return (await usersEntitledToClient(clientId)).length;
  } catch {
    return null;
  }
};

export function clientsRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '64kb' }));
  router.use(requireAdmin);

  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      res.set('cache-control', 'no-store');
      sendOk(res, {
        clients: await listClientDetails(entitled),
        viewerIsPlatformAdmin: await isPlatformAdminSession(session),
        protectedClients: [...PROTECTED],
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  // Everything below names a client: unknown ids are 404, and the mutations share one gate.
  router.param('clientId', (_req, res, next, clientId: string) => {
    if (!isManagedClient(clientId)) {
      sendError(res, 404, 'ERR-CLIENT-NOT-FOUND', 'No such application.');
      return;
    }
    next();
  });

  router.get('/:clientId', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const client = await getClientDetails(String(req.params.clientId), entitled);
      if (!client) {
        sendError(res, 404, 'ERR-CLIENT-NOT-FOUND', 'No such application.');
        return;
      }
      res.set('cache-control', 'no-store');
      sendOk(res, { client, csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

  async function gate(req: Request, res: Response): Promise<{ clientId: string; session: PortalSession; actor: string } | null> {
    const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
    if (!(await isPlatformAdminSession(session))) {
      sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Only the platform administrator can change an application’s sign-in settings: they decide who receives a sign-in.');
      return null;
    }
    if (!validateAdminApiCsrf(req)) {
      sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
      return null;
    }
    return { clientId: String(req.params.clientId), session, actor: 'platform' };
  }

  const protectedRefusal = (res: Response, what: string) =>
    sendError(res, 409, 'ERR-CLIENT-PROTECTED', `The portal client cannot be ${what} from the console: the console itself signs in through it and a mistake would lock every administrator out. Use "Restore configured addresses" if it needs repairing.`);

  async function respondWithClient(res: Response, clientId: string, status = 200, extra: Record<string, unknown> = {}) {
    const client = await getClientDetails(clientId, entitled);
    sendOk(res, { client, csrf: issueAdminCsrf(res), ...extra }, status);
  }

  router.put('/:clientId/uris', requireOwnerAuthorisation('client.uris.update', (req) => String(req.params.clientId)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res);
      if (!g) return;
      if (PROTECTED.has(g.clientId)) return protectedRefusal(res, 'edited');
      const body = req.body as { redirectUris?: unknown; postLogoutRedirectUris?: unknown };
      const rules = { isProd: IDP_CONFIG.isProd, env: IDP_CONFIG.env };
      const redirect = validateClientUris(body.redirectUris, { ...rules, allowEmpty: false }, 'Redirect address');
      if (!redirect.ok) return sendError(res, 400, 'ERR-VALIDATION-FAILED', redirect.error);
      const logout = validateClientUris(body.postLogoutRedirectUris ?? [], { ...rules, allowEmpty: true }, 'Sign-out address');
      if (!logout.ok) return sendError(res, 400, 'ERR-VALIDATION-FAILED', logout.error);
      // GMS's bridge is a client of this service: its own callback must stay registered or the GMS tile stops working.
      if (g.clientId === 'gms' && !redirect.value.some((u) => new URL(u).pathname.endsWith('/bridge/gms/callback'))) {
        return sendError(res, 400, 'ERR-VALIDATION-FAILED', 'The GMS bridge’s own callback (…/bridge/gms/callback) must stay in the list; without it the GMS tile cannot sign anyone in.');
      }
      const change = await updateClientUris(g.clientId, { redirect: redirect.value, logout: logout.value }, g.actor);
      await writeAudit(req, g.session.email, 'client.uris.update', g.clientId, { before: change.before, after: change.after });
      await respondWithClient(res, g.clientId);
    } catch (err) {
      next(err);
    }
  });

  router.post('/:clientId/restore-uris', requireOwnerAuthorisation('client.uris.restore', (req) => String(req.params.clientId)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res);
      if (!g) return;
      const seed = IDP_CONFIG.clientSeed.find((c) => c.client_id === g.clientId);
      if (!seed) return sendError(res, 404, 'ERR-CLIENT-NOT-FOUND', 'No such application.');
      const change = await updateClientUris(g.clientId, { redirect: seed.redirect_uris, logout: seed.post_logout_redirect_uris ?? [] }, g.actor);
      await writeAudit(req, g.session.email, 'client.uris.restore', g.clientId, { before: change.before, after: change.after });
      await respondWithClient(res, g.clientId);
    } catch (err) {
      next(err);
    }
  });

  router.put('/:clientId/active', requireOwnerAuthorisation('client.active.set', (req) => String(req.params.clientId)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res);
      if (!g) return;
      const active = (req.body as { active?: unknown })?.active;
      if (typeof active !== 'boolean') return sendError(res, 400, 'ERR-VALIDATION-FAILED', '"active" must be true or false.');
      if (PROTECTED.has(g.clientId)) return protectedRefusal(res, 'switched off');
      const { revokedArtifacts } = await setClientActive(g.clientId, active, g.actor);
      await writeAudit(req, g.session.email, active ? 'client.enable' : 'client.disable', g.clientId, { revokedArtifacts });
      await respondWithClient(res, g.clientId, 200, { revokedArtifacts });
    } catch (err) {
      next(err);
    }
  });

  router.post('/:clientId/rotate-secret', requireOwnerAuthorisation('client.secret.rotate', (req) => String(req.params.clientId)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res);
      if (!g) return;
      if (PROTECTED.has(g.clientId)) return protectedRefusal(res, 'given a new secret');
      // Typing the id is the second key: a rotation breaks the application until its own configuration is updated.
      if ((req.body as { confirm?: unknown })?.confirm !== g.clientId) {
        return sendError(res, 400, 'ERR-CONFIRMATION-REQUIRED', `Type the application id (${g.clientId}) to confirm.`);
      }
      const secret = await rotateClientSecret(g.clientId, g.actor);
      // The secret itself is never logged or audited; only that a rotation happened.
      await writeAudit(req, g.session.email, 'client.secret.rotate', g.clientId, {});
      res.set('cache-control', 'no-store');
      await respondWithClient(res, g.clientId, 200, { secret });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
