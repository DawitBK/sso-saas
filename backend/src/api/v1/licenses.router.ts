/**
 * Platform licensing API (docs/operations/PLATFORM-LICENSING.md section 5). Everything is under /api/v1, the prefix SSO's other APIs use.
 *
 *   GET    /api/v1/licenses/public/:system      UNAUTHENTICATED, rate-limited: 200 { token } (also { data: { token } }), or 404 when that system has no licence.
 *                                               The token is a signed JWS that holds no secret; GMS and DMS poll it (see licenses/token.ts).
 *   GET    /api/v1/licenses/public/sso-expiry   UNAUTHENTICATED: 200 { token } = the "SSO ends on this date" note (licenses/ceiling.ts), or 404 when SSO has no licence.
 *   GET    /api/v1/licenses/status              SSO's own status (contract section 5 shape), the platform administrator only. Also served at /api/v1/license/status.
 *   GET    /api/v1/admin/licenses               every system's licence, state, the module catalogue and the last changes     (platform administrator)
 *   PUT    /api/v1/admin/licenses/:system       create or update ({ customer, expiresAt|null, graceDays, warnDays, maxUsers|null, modules|null, notes, csrf })
 *   POST   /api/v1/admin/licenses/:system/extend  { days } or { expiresAt }, plus csrf
 *   DELETE /api/v1/admin/licenses/:system       revoke: the system returns to "no licence" ({ csrf })
 *   GET    /api/v1/admin/licenses/:system/events  the history of one system (?limit=)
 *
 * The admin routes belong to the platform administrator alone, the line the signing keys and the application settings draw (the IdP
 * administrator group opens the console; it does not decide what the customer has paid for). Every change is audited twice: the append-only
 * license_events table and the tamper-evident admin audit chain.
 */
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { getPortalSessionFromRequest, requireAdminJson } from '../../admin/requireAdmin.js';
import { isPlatformAdminSession } from '../../auth/platform-admin.js';
import { IDP_CONFIG } from '../../config.js';
import { createLimiter } from '../../infrastructure/rateLimiter.js';
import type { PortalSession } from '../../portal/session.js';
import { LICENSE_SYSTEMS, MODULE_CATALOG, SYSTEM_LABELS, isLicenseSystem, type LicenseSystem } from '../../licenses/catalog.js';
import { signCeilingToken } from '../../licenses/ceiling.js';
import { followSso } from '../../licenses/follow.js';
import { findLicense, highestVersionEver, listEvents, listLicenseRecords } from '../../licenses/repository.js';
import { pool } from '../../db/pool.js';
import { LicenseError, extendLicense, revokeLicense, saveLicense, type Actor } from '../../licenses/service.js';
import { ownLicenseStatus } from '../../licenses/status.js';
import { computeLicenseState } from '../../licenses/state.js';
import { signLicenseToken } from '../../licenses/token.js';
import { requireOwnerAuthorisation } from '../../owner/middleware.js';
import { issueAdminCsrf, validateAdminApiCsrf } from './admin.router.js';
import { sendError, sendOk } from './platform.router.js';
import { logger } from '../../logging/logger.js';

function answerLicenseError(res: Response, err: unknown): boolean {
  if (err instanceof LicenseError) {
    sendError(res, err.status, err.code, err.message, err.details);
    return true;
  }
  return false;
}

/** Public token and own status. Mounted at /licenses and /license. */
export function licensesPublicRouter(): Router {
  const router = Router();

  // 60 a minute per address: GMS and DMS poll every 5 minutes (from the same loopback address on this server), so this is generous.
  const publicLimiter = createLimiter('license-public', { windowMs: 60_000, limit: 60 });

  // The "SSO ends on this date" note for clients that hold OFFLINE licences (licenses/ceiling.ts). Declared before /public/:system so the path is not read as a system.
  router.get('/public/sso-expiry', publicLimiter, async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const sso = await findLicense('sso');
      if (!sso) {
        sendError(res, 404, 'ERR-LICENSE-NOT-FOUND', 'No licence for SSO.');
        return;
      }
      const token = await signCeilingToken(sso, await highestVersionEver('sso', pool));
      res.set('cache-control', 'no-store');
      res.status(200).json({ token, data: { token }, meta: { requestId: String(res.locals.requestId ?? '') } });
    } catch (err) {
      logger.error({ err, requestId: res.locals.requestId }, '[idp:license] could not issue the SSO expiry note');
      next(err);
    }
  });

  router.get('/public/:system', publicLimiter, async (req: Request, res: Response, next: NextFunction) => {
    try {
      const system = String(req.params.system);
      // An unknown system is indistinguishable from one with no licence.
      const license = isLicenseSystem(system) ? await findLicense(system) : null;
      if (!license) {
        sendError(res, 404, 'ERR-LICENSE-NOT-FOUND', 'No licence for this system.');
        return;
      }
      // A client's token follows SSO's own expiry (owner decision 2026-10-21, licenses/follow.ts): whichever ends first counts.
      const effective = followSso(license, await findLicense('sso'), await highestVersionEver('sso', pool));
      const token = await signLicenseToken(effective);
      res.set('cache-control', 'no-store');
      // `token` at the top level is the contract's `200 { token }`; `data.token` is SSO's usual envelope. Both carry the same string.
      res.status(200).json({ token, data: { token }, meta: { requestId: String(res.locals.requestId ?? '') } });
    } catch (err) {
      logger.error({ err, requestId: res.locals.requestId }, '[idp:license] could not issue a licence token');
      next(err);
    }
  });

  router.get('/status', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = await getPortalSessionFromRequest(req);
      if (!session) {
        sendError(res, 401, 'ERR-NOT-AUTHENTICATED', 'Authentication required');
        return;
      }
      // SSO's own licence is the platform administrator's to see (owner decision 2026-10-19): an IdP administrator gets no licence information.
      if (!(await isPlatformAdminSession(session))) {
        sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Licences are visible to the platform administrator only.');
        return;
      }
      res.set('cache-control', 'no-store');
      sendOk(res, await ownLicenseStatus());
    } catch (err) {
      next(err);
    }
  });

  return router;
}

export function licensesAdminRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '64kb' }));
  router.use(requireAdminJson(sendError));

  /** Common gate: the platform administrator, a valid CSRF token for anything that changes state. */
  async function gate(req: Request, res: Response, mutating: boolean): Promise<{ session: PortalSession; actor: Actor } | null> {
    const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
    const isPlatform = await isPlatformAdminSession(session);
    if (!isPlatform) {
      sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Licences are managed by the platform administrator only.');
      return null;
    }
    if (mutating && !validateAdminApiCsrf(req)) {
      sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
      return null;
    }
    // The platform administrator is recorded as 'platform', never by address (auth/platform-admin.ts).
    return { session, actor: { email: session.email, label: 'platform' } };
  }

  router.param('system', (_req, res, next, system: string) => {
    if (!isLicenseSystem(system)) {
      sendError(res, 404, 'ERR-LICENSE-SYSTEM-NOT-FOUND', 'No such system. Use sso, gms or dms.');
      return;
    }
    next();
  });

  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!(await gate(req, res, false))) return;
      const now = Date.now();
      const records = new Map((await listLicenseRecords()).map((r) => [r.system, r]));
      const systems = await Promise.all(
        LICENSE_SYSTEMS.map(async (system) => {
          const license = records.get(system) ?? null;
          return {
            system,
            label: SYSTEM_LABELS[system],
            modules: MODULE_CATALOG[system],
            license,
            computed: computeLicenseState(license, now),
            events: await listEvents(system, 20),
          };
        }),
      );
      res.set('cache-control', 'no-store');
      sendOk(res, { systems, enforcement: IDP_CONFIG.licenseEnforcement, serverTime: new Date(now).toISOString(), csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

  router.get('/:system/events', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!(await gate(req, res, false))) return;
      const limit = Number(req.query.limit);
      res.set('cache-control', 'no-store');
      sendOk(res, { events: await listEvents(req.params.system as LicenseSystem, Number.isFinite(limit) && limit > 0 ? limit : 50) });
    } catch (err) {
      next(err);
    }
  });

  router.put('/:system', requireOwnerAuthorisation('license.save', (req) => String(req.params.system)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res, true);
      if (!g) return;
      const { license, action } = await saveLicense(req, g.actor, req.params.system as LicenseSystem, req.body);
      sendOk(res, { license, action, computed: computeLicenseState(license, Date.now()), csrf: issueAdminCsrf(res) }, action === 'create' ? 201 : 200);
    } catch (err) {
      if (!answerLicenseError(res, err)) next(err);
    }
  });

  router.post('/:system/extend', requireOwnerAuthorisation('license.extend', (req) => String(req.params.system)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res, true);
      if (!g) return;
      const license = await extendLicense(req, g.actor, req.params.system as LicenseSystem, req.body);
      sendOk(res, { license, computed: computeLicenseState(license, Date.now()), csrf: issueAdminCsrf(res) });
    } catch (err) {
      if (!answerLicenseError(res, err)) next(err);
    }
  });

  router.delete('/:system', requireOwnerAuthorisation('license.revoke', (req) => String(req.params.system)), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res, true);
      if (!g) return;
      await revokeLicense(req, g.actor, req.params.system as LicenseSystem);
      sendOk(res, { system: req.params.system, license: null, csrf: issueAdminCsrf(res) });
    } catch (err) {
      if (!answerLicenseError(res, err)) next(err);
    }
  });

  return router;
}
