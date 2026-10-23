/**
 * The app-launcher catalog — the single source of truth for which systems
 * appear on the portal and where each tile points.
 *
 * WHY THIS IS ITS OWN MODULE: there are two portal surfaces — the view-model
 * one (portal/router.ts) and the JSON one the Next.js frontend consumes
 * (api/v1/portal.router.ts) — and they each used to carry their own copy of
 * this list. When a fourth system was added it updated only one of them, so
 * that system was loggable-into but invisible on the launcher until it was
 * found and fixed separately. One list, imported twice, makes that class of
 * drift impossible.
 *
 * Registering an OIDC client (config.ts's clientSeed) still does NOT create a
 * tile, and adding a tile does not create a client. A new system needs both:
 * its clientSeed entry and its APP_REGISTRY entry below (the admin console's
 * App access list derives from the latter, so there is no third list).
 */

import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { parseProductTiles } from '../oidc/product-clients.js';
import { getList } from '../settings/store.js';

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
 * https://portal.examplecorp.com/bridge/gms/start — which Apache has no rule
 * for, so the GMS and admin tiles 404'd from the docroot while the rest of the
 * portal worked fine.
 *
 * Cross-system tiles (EDAMS) are absolute, env-driven URLs living at their
 * own Apache prefixes, and must pass through untouched.
 */
const ownUrl = (path: string): string => `${IDP_CONFIG.publicBasePath}${path}`;

/**
 * THE one list of launcher systems: portal tile AND the admin console's "App access"
 * checkboxes / entitlement allowlist both derive from it (admin/access.ts's `APPS` is
 * `APP_REGISTRY` stripped to rp+label). It used to be a separate hand-kept list in
 * admin/access.ts, which a new system could silently miss.
 *
 * `enabled` gates only the TILE. The entitlement list deliberately ignores it, so
 * switching a system off temporarily does not make the console drop (on the next save)
 * the groups' existing entitlement rows for it.
 *
 * A new system still ALSO needs its OIDC client in config.ts's `clientSeed`
 * (`rp` here is that client's id, or the bridge's name for GMS).
 */
export const APP_REGISTRY: ReadonlyArray<{
  rp: string;
  /** Short name in the admin console's App access list. */
  label: string;
  /** Tile title on the launcher. */
  name: string;
  enabled: () => boolean;
  url: () => string;
}> = [
  {
    rp: 'edams',
    label: 'EDAMS (DMS)',
    name: 'EDAMS — Document Management',
    enabled: () => IDP_CONFIG.dms.enabled,
    url: () => IDP_CONFIG.dms.authorizeUrl,
  },
  {
    rp: 'gms',
    label: 'GMS',
    name: 'GMS — Guest Management',
    enabled: () => IDP_CONFIG.gms.enabled,
    url: () => ownUrl('/bridge/gms/start'),
  },
  // MOS (on Odoo) is registered, like its OIDC client in config.ts, only when MOS_ENABLED=true. Its tile opens MOS's own
  // sign-in start, which sends the person straight back through this IdP; with no MOS_PORTAL_URL there is no tile.
  ...(process.env.MOS_ENABLED === 'true'
    ? [
        {
          rp: 'mos',
          label: 'MOS (Odoo)',
          name: 'MOS — Manufacturing Operations',
          enabled: () => Boolean(process.env.MOS_PORTAL_URL),
          url: () => process.env.MOS_PORTAL_URL ?? '',
        },
      ]
    : []),
  // Other applications (oidc/product-clients.ts): PRODUCT_APPS_JSON is a JSON list of {rp, label, name, url}; absent or empty means none.
  ...parseProductTiles(process.env.PRODUCT_APPS_JSON).map((t) => ({ rp: t.rp, label: t.label, name: t.name, enabled: () => true, url: () => t.url })),
];

/** Full app catalog; filtered per-user by entitlement below. */
export function catalog(): AppTile[] {
  // portal.hiddenApps (platform setting): taken off the launcher for everyone; access rules are untouched.
  const hidden = getList('portal.hiddenApps');
  return APP_REGISTRY.filter((a) => a.enabled() && !hidden.includes(a.rp)).map((a) => ({
    rp: a.rp,
    name: a.name,
    url: a.url(),
    mode: 'Open',
  }));
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
