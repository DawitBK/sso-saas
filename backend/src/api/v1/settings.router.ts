/**
 * Platform settings API.
 *
 *   GET    /api/v1/admin/settings        every setting, grouped, with its limits, current value, default and who may change it
 *   PUT    /api/v1/admin/settings/:key   change one ({ value, csrf })
 *   DELETE /api/v1/admin/settings/:key   put one back to its default ({ csrf })
 *   GET    /api/v1/public/branding       the few values the sign-in page and portal need before anyone is signed in
 *
 * The console renders itself from GET (settings/registry.ts is the source), so the UI cannot offer a control the backend would refuse.
 * A change is validated, stored, applied in this process at once, and written to the admin audit chain with the old and new value.
 * Settings marked `platform` (password rules, lockout, two-factor, token lifetimes, retention) are the platform administrator's alone.
 */
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { writeAudit } from '../../admin/audit.js';
import { isPlatformAdminSession } from '../../auth/platform-admin.js';
import type { PortalSession } from '../../portal/session.js';
import { SETTING_GROUPS, readableInk, settingDef, type SettingDef } from '../../settings/registry.js';
import { getBool, getNumber, getString, listSettingStates, resetSetting, setSetting } from '../../settings/store.js';
import { APP_REGISTRY } from '../../portal/catalog.js';
import { issueAdminCsrf, validateAdminApiCsrf } from './admin.router.js';
import { sendError, sendOk } from './platform.router.js';

const requireAdmin = requireAdminJson(sendError);

/** How an `updated_by` value is shown: the platform administrator stays anonymous. */
function actorLabel(updatedBy: string | null): string | null {
  if (!updatedBy) return null;
  return updatedBy === 'platform' ? 'Platform administrator' : updatedBy;
}

function describeDef(def: SettingDef) {
  return {
    key: def.key,
    label: def.label,
    help: def.help,
    type: def.type,
    min: def.min ?? null,
    max: def.max ?? null,
    unit: def.unit ?? null,
    maxLength: def.maxLength ?? null,
    multiline: Boolean(def.multiline),
    editableBy: def.editableBy,
    applies: def.applies,
    // The `apps` type offers the launcher's applications, by the name an administrator knows them under.
    choices: def.type === 'apps' ? APP_REGISTRY.map((a) => ({ id: a.rp, label: a.label })) : null,
  };
}

export function settingsAdminRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '64kb' }));
  router.use(requireAdmin);

  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      const viewerIsPlatformAdmin = await isPlatformAdminSession(session);
      const states = listSettingStates();
      res.set('cache-control', 'no-store');
      sendOk(res, {
        viewerIsPlatformAdmin,
        groups: SETTING_GROUPS.map((g) => ({
          ...g,
          settings: states
            .filter((s) => s.def.group === g.id)
            .map((s) => ({
              ...describeDef(s.def),
              value: s.value,
              defaultValue: s.defaultValue,
              source: s.source,
              updatedAt: s.updatedAt,
              updatedBy: actorLabel(s.updatedBy),
              canEdit: s.def.editableBy === 'admin' || viewerIsPlatformAdmin,
            })),
        })),
        csrf: issueAdminCsrf(res),
      });
    } catch (err) {
      next(err);
    }
  });

  /** Common gate for PUT and DELETE: known key, the right to change it, a valid CSRF token. */
  async function gate(req: Request, res: Response): Promise<{ def: SettingDef; session: PortalSession; actor: string } | null> {
    const def = settingDef(String(req.params.key));
    if (!def) {
      sendError(res, 404, 'ERR-SETTING-NOT-FOUND', 'No such setting.');
      return null;
    }
    const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
    const isPlatform = await isPlatformAdminSession(session);
    if (def.editableBy === 'platform' && !isPlatform) {
      sendError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', `"${def.label}" can only be changed by the platform administrator.`);
      return null;
    }
    if (!validateAdminApiCsrf(req)) {
      sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
      return null;
    }
    // The platform administrator is recorded as 'platform', never by address (auth/platform-admin.ts).
    return { def, session, actor: isPlatform ? 'platform' : session.email };
  }

  router.put('/:key', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res);
      if (!g) return;
      const result = await setSetting(g.def.key, (req.body as { value?: unknown })?.value, g.actor);
      if (!result.ok) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', result.error);
        return;
      }
      await writeAudit(req, g.session.email, 'setting.update', g.def.key, { before: result.change.before, after: result.change.after });
      sendOk(res, { key: g.def.key, value: result.change.after, source: 'stored', csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

  router.delete('/:key', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const g = await gate(req, res);
      if (!g) return;
      const result = await resetSetting(g.def.key);
      if (!result.ok) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', result.error);
        return;
      }
      await writeAudit(req, g.session.email, 'setting.reset', g.def.key, { before: result.change.before, after: result.change.after });
      sendOk(res, { key: g.def.key, value: result.change.after, source: 'default', csrf: issueAdminCsrf(res) });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

/**
 * GET /api/v1/admin/csrf: a fresh CSRF token (and its cookie) for any console page that is about to mutate and has no GET of its own
 * that issues one (Users bulk actions). Double-submit: the cookie is httpOnly, the token travels in the body.
 */
export function csrfRouter(): Router {
  const router = Router();
  router.use(requireAdmin);
  router.get('/', (_req: Request, res: Response) => {
    res.set('cache-control', 'no-store');
    sendOk(res, { csrf: issueAdminCsrf(res) });
  });
  return router;
}

/** Everything the unauthenticated pages may know. Nothing here is secret; it is all text shown on the sign-in page anyway. */
export function publicBranding() {
  const accent = getString('branding.accentColor');
  const accentDark = getString('branding.accentColorDark');
  return {
    productName: getString('branding.productName'),
    tagline: getString('branding.tagline'),
    accentColor: accent,
    accentInk: readableInk(accent),
    accentColorDark: accentDark,
    accentInkDark: readableInk(accentDark),
    loginNotice: getString('branding.loginNotice'),
    supportContact: getString('branding.supportContact'),
    footerText: getString('branding.footerText'),
    portalMessage: getString('portal.welcomeMessage'),
    // The sign-in page's "set a new password" form states the real rule instead of a hard-coded 8.
    passwordMinLength: getNumber('password.minLength'),
    // Whether the sign-in page offers "Forgot your password?".
    passwordResetRequests: getBool('password.allowResetRequests'),
  };
}

export function publicRouter(): Router {
  const router = Router();
  router.get('/branding', (_req: Request, res: Response) => {
    // Short shared cache: a branding change shows up within seconds, and a flood of sign-in page loads costs nothing.
    res.set('cache-control', 'public, max-age=15, stale-while-revalidate=60');
    sendOk(res, publicBranding());
  });
  return router;
}
