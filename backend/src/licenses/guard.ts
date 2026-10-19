/**
 * SSO's own read-only guard (docs/operations/PLATFORM-LICENSING.md section 6): while SSO's OWN licence is `expired` (past expiry AND past the
 * grace period), every POST/PUT/PATCH/DELETE is refused with 403 `LICENSE_EXPIRED` unless its path is on the allowlist below. Safe methods
 * always pass. No licence row for SSO, a licence that is not expired, `LICENSE_ENFORCEMENT=warn` or `off`, or a database that cannot be read:
 * the guard does nothing at all (it fails OPEN; an IdP that locks everyone out of every system by accident is the worst outcome here).
 *
 * Default-deny with an allowlist, mounted ahead of every route in main.ts, so a new admin mutation under /api/v1/admin is read-only at expiry
 * without anyone remembering to guard it. The allowlist is the sign-in surface and must be kept complete: if you add a route someone needs in
 * order to SIGN IN, add it here and add a test in tests/license-guard.test.ts (one test per entry exists for exactly that reason).
 *
 * Allowlisted (matched on whole path segments, so `/portal` allows `/portal/login` but not `/portalx`):
 *   sign-in and OIDC      /interaction  /authorize  /token (+ introspection, revocation)  /me  /session  /device  /.well-known  /jwks
 *   the portal, bridges   /portal  /bridge  /api/v1/auth  /api/v1/portal  /api/v1/public
 *   health                /health  /metrics  /api/v1/health  /api/v1/metrics
 *   licences              /api/v1/licenses  /api/v1/license  /api/v1/admin/licenses  /api/v1/admin/csrf
 *   system to system      /api/v1/internal  /internal   (GMS managing its own role grants: not a console mutation)
 *   security emergencies  /api/v1/admin/keys   (rotating or withdrawing a signing key must stay possible when a key leaks)
 * Everything else that mutates, i.e. the rest of the admin console (users, groups, settings, applications, sessions, reset requests, bulk
 * actions, audit acknowledgements), is read-only.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';
import { computeLicenseState } from './state.js';
import { ownLicenseRecord } from './status.js';
import type { LicenseEnforcement } from './enforcement.js';

export const LICENSE_EXPIRED_MESSAGE = 'The licence has expired; the system is read-only. Contact your administrator.';

export const READ_ONLY_ALLOWLIST: readonly string[] = [
  '/interaction', '/authorize', '/token', '/me', '/session', '/device', '/.well-known', '/jwks',
  '/portal', '/bridge', '/api/v1/auth', '/api/v1/portal', '/api/v1/public',
  '/health', '/metrics', '/api/v1/health', '/api/v1/metrics',
  '/api/v1/licenses', '/api/v1/license', '/api/v1/admin/licenses', '/api/v1/admin/csrf',
  '/api/v1/internal', '/internal',
  '/api/v1/admin/keys',
];

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Whole-segment prefix match: `/portal` matches `/portal` and `/portal/x`, never `/portalx`. */
export function isAllowlisted(path: string, allowlist: readonly string[] = READ_ONLY_ALLOWLIST): boolean {
  const p = path.length > 1 ? path.replace(/\/+$/, '') : path;
  return allowlist.some((prefix) => p === prefix || p.startsWith(`${prefix}/`));
}

export interface GuardDeps {
  mode: () => LicenseEnforcement;
  /** Whether SSO's own licence is expired right now. Must not throw; fail open (false) when it cannot tell. */
  expired: () => Promise<boolean>;
}

const defaultDeps: GuardDeps = {
  mode: () => IDP_CONFIG.licenseEnforcement,
  expired: async () => {
    try {
      return computeLicenseState(await ownLicenseRecord(), Date.now()).state === 'expired';
    } catch {
      return false;
    }
  },
};

let lastWarnAt = 0;

export function licenseReadOnlyGuard(deps: GuardDeps = defaultDeps): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const mode = deps.mode();
      if (mode === 'off' || SAFE_METHODS.has(req.method) || isAllowlisted(req.path)) {
        next();
        return;
      }
      if (!(await deps.expired())) {
        next();
        return;
      }
      if (mode === 'warn') {
        // Warn only (LICENSE_ENFORCEMENT=warn): the request goes through, with a log line at most once a minute.
        if (Date.now() - lastWarnAt > 60_000) {
          lastWarnAt = Date.now();
          logger.warn({ method: req.method, path: req.path }, '[idp:license] SSO’s licence has expired; LICENSE_ENFORCEMENT=warn, so this change was NOT refused');
        }
        next();
        return;
      }
      res.status(403).json({
        error: { code: 'LICENSE_EXPIRED', message: LICENSE_EXPIRED_MESSAGE },
        meta: { requestId: String(res.locals.requestId ?? '') },
      });
    } catch (err) {
      // Never let the guard itself turn into an outage.
      logger.warn({ err }, '[idp:license] guard failed; letting the request through');
      next();
    }
  };
}
