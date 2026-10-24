/**
 * Read-only containment for SSO while an incident lock is in force (ops/incidentLock.ts): every POST/PUT/PATCH/DELETE answers 403 `INCIDENT_READ_ONLY`
 * unless its path is on the licence guard's allowlist (sign-in and OIDC, the portal, health, the licence routes, system-to-system calls and the signing-key
 * emergency routes: licenses/guard.ts READ_ONLY_ALLOWLIST, reused so the two read-only states can never drift apart). Safe methods always pass.
 *
 * Mounted next to licenseReadOnlyGuard in main.ts. With no INCIDENT_LOCK_FILE and no in-process lock the guard does nothing, and it never throws.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { IDP_CONFIG } from '../config.js';
import { isAllowlisted } from '../licenses/guard.js';
import { INCIDENT_READ_ONLY_MESSAGE, activeIncidentLock, type IncidentLockInfo } from './incidentLock.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Allowed on top of the licence guard's list while locked:
 *  - the owner's own verification sequence (questions, e-mailed code, authenticator, recovery codes). It needs the owner's session AND their factors, and it
 *    is how the owner proves who they are to do anything owner-only during an incident (rotate or withdraw a key, change a licence);
 *  - the acknowledgement of a known break in the audit log (`POST /api/v1/admin/audit/chain-acknowledgements`). A broken audit log is itself what locks the
 *    platform, so without this the only way out of an old, explained break would be refused by the lock it caused. The route is the platform administrator's
 *    alone AND needs the owner's one-time authorisation (owner operation `audit.chain.acknowledge`) AND the console's CSRF token, all checked by the route
 *    itself after this guard; an acknowledgement never clears the lock and only covers a break already on record (admin/audit.ts acknowledgeChainBreak).
 * Matching is by whole path segment (licenses/guard.ts isAllowlisted): `/api/v1/admin/audit/chain-acknowledgementsx` and `/api/v1/admin/audit` are NOT allowed.
 * Clearing the lock itself is still only the terminal command (the watcher's clear command).
 */
export const INCIDENT_EXTRA_ALLOWLIST: readonly string[] = ['/api/v1/owner/verification', '/api/v1/admin/audit/chain-acknowledgements'];

export interface IncidentGuardDeps {
  lock: () => IncidentLockInfo | null;
}

const defaultDeps: IncidentGuardDeps = { lock: () => activeIncidentLock(IDP_CONFIG.incidentLockFile) };

export function incidentReadOnlyGuard(deps: IncidentGuardDeps = defaultDeps): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (SAFE_METHODS.has(req.method) || isAllowlisted(req.path) || isAllowlisted(req.path, INCIDENT_EXTRA_ALLOWLIST)) {
        next();
        return;
      }
      if (!deps.lock()) {
        next();
        return;
      }
      res.status(403).json({
        error: { code: 'INCIDENT_READ_ONLY', message: INCIDENT_READ_ONLY_MESSAGE },
        meta: { requestId: String(res.locals.requestId ?? '') },
      });
    } catch {
      // Never let the guard itself turn into an outage.
      next();
    }
  };
}
