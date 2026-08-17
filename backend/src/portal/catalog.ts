/**
 * The app-launcher catalog — the single source of truth for which systems
 * appear on the portal and where each tile points.
 *
 * WHY THIS IS ITS OWN MODULE: there are two portal surfaces — the server-
 * rendered EJS one (portal/router.ts) and the JSON one the Next.js frontend
 * consumes (api/v1/portal.router.ts) — and they each used to carry their own
 * copy of this list. Adding MRS updated only one of them, so MRS was
 * loggable-into but invisible on the launcher until that was found and fixed
 * separately (see the note in the root CLAUDE.md). One list, imported twice,
 * makes that class of drift impossible.
 */

import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';

export interface AppTile {
  rp: string;
  name: string;
  url: string;
  mode: string;
}

/**
 * Tile URLs that point back into THIS service must carry publicBasePath.
 *
 * A tile href is followed by the browser as a plain top-level navigation — it
 * is not a `res.redirect()`, so main.ts's Location-header prefixing never sees
 * it, and it is not a `next/link`, so Next's basePath never rewrites it either
 * (app/portal/page.tsx renders `<a href={app.url}>` with the value verbatim).
 * A bare '/bridge/gms/start' therefore resolved at the DOMAIN root —
 * https://portal.examplecorp.com/bridge/gms/start — which nginx has no rule
 * for, so the GMS and admin tiles 404'd from the docroot while the rest of the
 * portal worked fine.
 *
 * Cross-system tiles (EDAMS/MRS) are absolute, env-driven URLs living at their
 * own reverse-proxy prefixes, and must pass through untouched.
 */
const ownUrl = (path: string): string => `${IDP_CONFIG.publicBasePath}${path}`;

/** Full app catalog; filtered per-user by entitlement below. */
export function catalog(): AppTile[] {
  const apps: AppTile[] = [];
  if (IDP_CONFIG.dms.enabled) {
    apps.push({
      rp: 'edams',
      name: 'EDAMS — Document Management',
      url: IDP_CONFIG.dms.authorizeUrl,
      mode: 'Open',
    });
  }
  if (IDP_CONFIG.gms.enabled) {
    apps.push({
      rp: 'gms',
      name: 'GMS — Guest Management',
      url: ownUrl('/bridge/gms/start'),
      mode: 'Open',
    });
  }
  if (IDP_CONFIG.mrs.enabled) {
    apps.push({
      rp: 'mrs',
      name: 'MRS — Meeting Room Booking',
      url: IDP_CONFIG.mrs.loginUrl,
      mode: 'Open',
    });
  }
  return apps;
}

/** The admin console tile, appended for admins by both portal surfaces. */
export function adminTile(): AppTile {
  return {
    rp: 'idp-admin',
    name: 'IdP Administration — users, roles & access',
    url: ownUrl('/admin'),
    mode: 'Open',
  };
}

/**
 * Filter apps by entitlement: an app is shown if the user has a matching group
 * in idp_app_entitlements for it, OR the app has no entitlement rows (open to
 * all authenticated staff). This is the personalization.
 */
export async function entitled(groups: string[]): Promise<Set<string>> {
  const { rows } = await pool.query<{ relying_party: string; group_dn: string }>(
    'SELECT relying_party, group_dn FROM idp_app_entitlements',
  );
  const configured = new Set(rows.map((r) => r.relying_party));
  const groupSet = new Set(groups);
  const allowed = new Set<string>();
  for (const app of catalog()) {
    if (!configured.has(app.rp)) { allowed.add(app.rp); continue; } // no rules → open
    if (rows.some((r) => r.relying_party === app.rp && groupSet.has(r.group_dn))) allowed.add(app.rp);
  }
  return allowed;
}
