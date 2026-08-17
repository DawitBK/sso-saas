/**
 * Example Corp Identity Provider — configuration.
 *
 * Production build on `oidc-provider` (Panva). All values are environment-driven
 * with dev-friendly defaults. See `.env.example` for the full surface.
 *
 * Reconciled from the scaffold + docs/idp/IDP_TDD.md:
 *   - Service identity: port 7300, issuer https://idp.examplecorp.com (dev http://localhost:7300)
 *   - Clients live in the `idp_clients` DB table (seeded from CLIENT_SEED below)
 *   - Identity source: AD-primary (ldapts) with a local Postgres user-store fallback
 */

import dotenv from "dotenv";
// Captured BEFORE the base .env load below, because that load uses
// override:true and the dev .env sets NODE_ENV=development — without this
// capture, an externally-set NODE_ENV=production (from the *:prod npm
// scripts' run-with-env.cjs wrapper) would get silently clobbered back to
// "development" by the dev file's own override:true load, and the
// .env.production layer a few lines down would never fire.
const externalNodeEnv = process.env.NODE_ENV;
// override:true so this service's .env wins over any inherited shell/global vars
// (e.g. a machine-wide DATABASE_URL pointing elsewhere).
const baseEnvLoad = dotenv.config({ override: true });
/**
 * Layer real production values on top ONLY when NODE_ENV=production was set
 * before this process started (see package.json's `*:prod` scripts, which set
 * it via scripts/run-with-env.cjs rather than relying on shell-specific syntax).
 * This means `.env` never has to hold — or be overwritten with — real prod
 * secrets: it stays the dev file, `.env.production` is the only place prod
 * values live, and the two can never be confused for each other by filename
 * alone. (Previously this service only ever read a bare `.env`, which is how
 * a hand-edited dev `.env` on the prod box silently ran migrations against
 * the dev DB — see git history around 2026-07-30.)
 */
let prodEnvLoad: ReturnType<typeof dotenv.config> | undefined;
if (externalNodeEnv === "production") {
  prodEnvLoad = dotenv.config({ path: ".env.production", override: true });
}

/**
 * override:true above only protects us when THIS service's own .env (or
 * .env.production) actually defines DATABASE_URL — dotenv only overrides keys
 * present in the loaded file, so a stray/machine-wide DATABASE_URL from the
 * shell environment still wins silently if that line is ever missing, blank,
 * or commented out (a fresh checkout, a bad merge, someone debugging). This
 * exact footgun has already bitten this platform more than once (see root
 * CLAUDE.md "Known footguns" — MRS needed two separate fixes for it). Refuse
 * to boot on an ambient DATABASE_URL neither env file defined, unless
 * DATABASE_URL_TRUSTED=1 explicitly says that's expected.
 */
if (
  process.env.DATABASE_URL &&
  !baseEnvLoad.parsed?.DATABASE_URL &&
  !prodEnvLoad?.parsed?.DATABASE_URL &&
  process.env.DATABASE_URL_TRUSTED !== "1"
) {
  throw new Error(
    "DATABASE_URL is set in the environment but not defined in this service's own .env" +
      (externalNodeEnv === "production" ? "/.env.production" : "") +
      " — refusing to boot against a possibly machine-wide/leftover DATABASE_URL. " +
      "If this is intentional, set DATABASE_URL_TRUSTED=1.",
  );
}

function env(name: string, fallback?: string): string {
  const v = process.env[name];
  if (v === undefined || v === "") {
    if (fallback === undefined) {
      throw new Error(`Missing required environment variable: ${name}`);
    }
    return fallback;
  }
  return v;
}

function envInt(name: string, fallback: number): number {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : Number(v);
}

const NODE_ENV = process.env.NODE_ENV ?? "development";
const explicitProd = NODE_ENV === "production";
const issuerUrl = env("IDP_ISSUER", "http://localhost:7301").replace(/\/$/, "");
const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i;
// Same loopback hosts as LOCAL_ORIGIN_RE, but matches with a path/query
// trailing the host too (LOCAL_ORIGIN_RE is anchored to end-of-string and
// only fires on a bare origin) — used to catch a dev-default *URL*
// (redirect_uris, sibling-system API bases) left unset in production.
const LOOPBACK_HOST_RE = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i;
/**
 * Independent backstop for the prod-safety checks below: NODE_ENV is a single
 * env var that's easy to forget on a real deploy, and every downstream
 * protection (secure cookies, HSTS, assertProdSafeDefaults) used to key off it
 * alone — forgetting to set it meant all of them silently no-op together. If
 * the browser-facing issuer isn't a local dev origin, treat this as production
 * for those purposes even when NODE_ENV itself was left unset.
 */
const isProd = explicitProd || !LOCAL_ORIGIN_RE.test(issuerUrl);

/**
 * Public path prefix this service is served under, DERIVED from IDP_ISSUER's
 * path rather than configured separately — so it can never drift from the
 * issuer (`""` for a root-hosted dev issuer like http://localhost:7301,
 * `"/sso"` for https://portal.examplecorp.com/sso).
 *
 * WHY THIS EXISTS: SSO was originally written to sit at a domain root, so its
 * routers emit root-relative locations — 29 `res.redirect('/portal...')` calls
 * plus oidc-provider's interaction URL. Under a subpath those send the browser
 * to portal.examplecorp.com/portal (a 404 from the reverse proxy) instead of .../sso/portal. One
 * middleware in main.ts prefixes root-relative redirects with this value, and
 * oidc/provider.ts's `interactions.url` prepends it, which covers all of them
 * without touching each call site.
 *
 * The frontend has the mirror-image problem (raw fetch() isn't rewritten by
 * Next's basePath) and solves it with shared/apiPath.ts.
 */
const publicBasePath = (() => {
  try {
    const p = new URL(issuerUrl).pathname.replace(/\/+$/, "");
    return p;
  } catch {
    return "";
  }
})();

/** Custom claim namespace shared with EDAMS/DMS (see DMS auth.routes.ts). */
export const AD_GROUPS_CLAIM = "https://edams.examplecorp.com/ad_groups";

/**
 * Well-known placeholder client secrets shipped for local dev only. Referenced
 * both by the prod fail-fast check below and by `seedClients()` (oidc/clients.ts),
 * which is allowed to overwrite a stuck DB row ONLY if it still holds one of these
 * — never a value an admin actually set.
 */
export const DEV_DEFAULT_CLIENT_SECRETS = [
  "edams-dev-secret",
  "gms-dev-secret",
  "portal-dev-secret",
  "mrs-dev-secret",
];

export const IDP_CONFIG = {
  env: NODE_ENV,
  isProd,

  /** Browser-facing issuer URL. Carried as `iss` on every token and OIDC discovery. */
  issuer: issuerUrl,
  /**
   * Path prefix this service is publicly served under (`""` when root-hosted).
   * Derived from `issuer` — see the note on `publicBasePath` above.
   */
  publicBasePath,
  /**
   * Reachable base URL of this backend process for server-side OIDC calls
   * (token exchange, JWKS fetch). Defaults to the API port when the browser
   * entry point is served separately on 7301.
   */
  internalUrl: (
    process.env.IDP_INTERNAL_URL ?? "http://localhost:7300"
  ).replace(/\/$/, ""),
  port: envInt("PORT", 7300),

  /**
   * Postgres connection for the IdP's OWN store (oidc artifacts + users/roles/clients).
   * Separate database (`idp`) on the shared local PG server — apps never share a DB.
   */
  databaseUrl: env(
    "DATABASE_URL",
    "postgres://postgres:change-me@localhost:5432/idp",
  ),

  /** Cookie signing keys for oidc-provider session/interaction cookies (the SSO backbone). */
  cookieKeys: env("COOKIE_KEYS", "dev-cookie-key-1,dev-cookie-key-2")
    .split(",")
    .map((k) => k.trim())
    .filter(Boolean),

  /**
   * How many reverse-proxy hops to trust for X-Forwarded-For (Express `trust
   * proxy`). Was `true` (trust any depth from anyone), which let a caller spoof
   * the IP that lands in idp_login_events / the brute-force anomaly alerts.
   * Default of 1 assumes a single fronting proxy/LB; raise via env if there's
   * another hop in front of that.
   */
  trustProxyHops: envInt("TRUST_PROXY_HOPS", 1),

  /** Symmetric key (AES-256-GCM) used to encrypt totp_secret at rest — derived by
   *  hashing whatever string is provided so any length env value works. */
  totpEncryptionKey: env(
    "TOTP_ENCRYPTION_KEY",
    "dev-only-totp-key-do-not-use-in-prod",
  ),

  /** HMAC-SHA256 key for the idp_admin_audit tamper-evident hash chain (see
   *  src/admin/audit.ts). Mirrors DMS's AUDIT_HMAC_SECRET (audit.service.ts) —
   *  a distinct value from every other secret here, so a leak of one doesn't
   *  also let an attacker forge audit entries. */
  auditHmacSecret: env(
    "IDP_AUDIT_HMAC_SECRET",
    "dev-only-audit-hmac-secret-do-not-use-in-prod",
  ),

  /** Token lifetimes (seconds). */
  ttl: {
    accessToken: envInt("TTL_ACCESS_TOKEN", 3600), // 1h
    idToken: envInt("TTL_ID_TOKEN", 3600), // 1h
    refreshToken: envInt("TTL_REFRESH_TOKEN", 86400), // 24h
    session: envInt("TTL_SESSION", 14 * 24 * 3600), // 14d SSO session
    interaction: envInt("TTL_INTERACTION", 3600), // 1h
    grant: envInt("TTL_GRANT", 14 * 24 * 3600),
  },

  /**
   * Admin console (`/admin`). Gated to members of this group — same idp_user_groups
   * membership used everywhere else, no separate permission system.
   */
  adminGroup:
    process.env.IDP_ADMIN_GROUP ??
    "CN=EDAMS_Admins,OU=Groups,DC=examplecorp,DC=com",

  /**
   * DMS (EDAMS). Three surfaces:
   *   - `authorizeUrl` — where the SSO portal's EDAMS tile sends the browser
   *     to kick off DMS's own OIDC authorization-code flow (DMS redirects from
   *     there to this IdP).
   *   - `apiBaseUrl` — the admin console's internal API calls into DMS's
   *     `/api/v1/internal/roles/...` endpoints with `x-internal-api-key` auth.
   *   - `backchannelLogoutUri` — where this IdP POSTs backchannel-logout
   *     JWTs when an IdP session ends so DMS can drop the matching one.
   *
   * Dev defaults use bare localhost ports (no reverse proxy). Prod is reached
   * through the shared nginx edge via `/dms` path prefix.
   */
  dms: {
    enabled: (process.env.DMS_ENABLED ?? "true") === "true",
    authorizeUrl:
      process.env.DMS_OIDC_AUTHORIZE_URL ??
      "http://localhost:7100/api/v1/auth/oidc/authorize",
    backchannelLogoutUri:
      process.env.DMS_BACKCHANNEL_LOGOUT_URI ??
      "http://localhost:7100/api/v1/auth/backchannel-logout",
    apiBaseUrl: process.env.DMS_API_BASE_URL ?? "http://localhost:7100/api/v1",
  },
  dmsInternalApiKey: process.env.DMS_INTERNAL_API_KEY ?? "",
  dmsDefaultTenant: process.env.DMS_DEFAULT_TENANT ?? "examplecorp",

  /** Active Directory / LDAP (AD-primary auth). Unset LDAP_URL to disable AD and use local-only. */
  ldap: {
    url: process.env.LDAP_URL ?? "", // e.g. ldap://ad.examplecorp.com:389
    bindDN: process.env.LDAP_BIND_DN ?? "",
    bindPassword: process.env.LDAP_BIND_PASSWORD ?? "",
    searchBase: process.env.LDAP_SEARCH_BASE ?? "OU=Users,DC=examplecorp,DC=com",
    usernameAttr: process.env.LDAP_USERNAME_ATTR ?? "userPrincipalName",
    timeoutMs: envInt("LDAP_TIMEOUT_MS", 5000),
  },

  /**
   * GMS token bridge and internal-admin client. SSO never signs GMS tokens or
   * opens GMS's database directly; it delegates those responsibilities to GMS's
   * authenticated internal API.
   */
  gms: {
    enabled: (process.env.GMS_BRIDGE_ENABLED ?? "true") === "true",
    internalApiKey: process.env.GMS_INTERNAL_API_KEY ?? "",
    /** Where the GMS SPA lives, so the bridge landing page can seed its session + redirect. */
    frontendUrl: process.env.GMS_FRONTEND_URL ?? "http://localhost:7201",
    /** GMS backend API base, for optional server-side calls. */
    apiBase: process.env.GMS_API_BASE ?? "http://localhost:7200/api/v1",
    /** GMS SPA localStorage key (Zustand persist). */
    sessionStorageKey: process.env.GMS_SESSION_KEY ?? "gms-auth-session",
    /**
     * Inbound direction: gates GMS calling INTO SSO's per-user role-grant API
     * (directive §6.3). Same shared-secret-name-on-both-sides convention as
     * DMS_INTERNAL_API_KEY — GMS presents this value, SSO checks it here.
     */
    rolesApiKey: process.env.SSO_ROLES_API_KEY ?? "",
  },

  /**
   * MRS — an app-launcher tile only (unlike GMS, MRS has no bridge/gateway:
   * its own backend does a normal OIDC authorization-code exchange against
   * this IdP, see MRS backend/src/controllers/authController.js). The portal
   * just needs to know where to send the browser to kick that off.
   */
  mrs: {
    enabled: (process.env.MRS_ENABLED ?? "true") === "true",
    loginUrl:
      process.env.MRS_SSO_LOGIN_URL ??
      "http://localhost:7400/api/auth/sso/login",
  },

  /**
   * Same-origin reverse-proxy gateway for the GMS SPA (closes the cross-origin
   * handoff). Served on a non-loopback host that resolves to 127.0.0.1 so the
   * GMS frontend honors a same-origin API base (its dev code force-routes to
   * :5000 only for literal localhost/127.0.0.1 hosts).
   */
  gateway: {
    port: envInt("GATEWAY_PORT", 4200),
    publicUrl: process.env.GATEWAY_URL ?? "http://gms.localtest.me:4200",
    gmsFrontendTarget:
      process.env.GMS_FRONTEND_TARGET ?? "http://localhost:7201",
    gmsApiTarget: process.env.GMS_API_TARGET ?? "http://localhost:7200",
  },

  /**
   * Registered relying parties, seeded into `idp_clients` on first boot.
   * Redirect URIs align with the scaffold defaults; override per environment.
   */
  clientSeed: [
    {
      client_id: "edams",
      client_secret: env("EDAMS_CLIENT_SECRET", "edams-dev-secret"),
      redirect_uris: (
        process.env.EDAMS_REDIRECT_URIS ?? "http://localhost:7101/auth/callback"
      ).split(","),
      name: "EDAMS Document Management",
      post_logout_redirect_uris: (
        process.env.EDAMS_LOGOUT_URIS ?? "http://localhost:7101/login"
      ).split(","),
    },
    {
      client_id: "gms",
      client_secret: env("GMS_CLIENT_SECRET", "gms-dev-secret"),
      redirect_uris: (
        process.env.GMS_REDIRECT_URIS ??
        `${env("IDP_ISSUER", "http://localhost:7301").replace(/\/$/, "")}/bridge/gms/callback`
      ).split(","),
      name: "GMS (Guest Management System)",
      post_logout_redirect_uris: (
        process.env.GMS_LOGOUT_URIS ?? "http://localhost:7201/login"
      ).split(","),
    },
    {
      // The SSO portal itself is a relying party of this IdP — that's how it
      // learns who is signed in (reusing the shared SSO session) to personalize.
      client_id: "portal",
      client_secret: env("PORTAL_CLIENT_SECRET", "portal-dev-secret"),
      redirect_uris: [
        `${env("IDP_ISSUER", "http://localhost:7301").replace(/\/$/, "")}/portal/callback`,
      ],
      name: "Example Corp SSO Portal",
      post_logout_redirect_uris: [
        `${env("IDP_ISSUER", "http://localhost:7301").replace(/\/$/, "")}/portal`,
      ],
    },
    {
      // MRS retains local accounts and JWTs; this is an additional OIDC login
      // option rather than a rewrite of its existing authorization model.
      client_id: "mrs",
      client_secret: env("MRS_CLIENT_SECRET", "mrs-dev-secret"),
      redirect_uris: (
        process.env.MRS_REDIRECT_URIS ??
        "http://localhost:7400/api/auth/sso/callback"
      ).split(","),
      name: "MRS (Meeting Room Management)",
      post_logout_redirect_uris: (
        process.env.MRS_LOGOUT_URIS ?? "http://localhost:7401/login"
      ).split(","),
    },
  ],
};

export type IdpConfig = typeof IDP_CONFIG;

/**
 * Fail fast in production rather than silently running with a well-known dev
 * placeholder secret (client secrets, DB password, cookie keys, GMS refresh
 * secret defaulting to the access secret) — the kind of gap that only surfaces
 * later as "how long has this been like this."
 */
/**
 * Catches the *newer* placeholder convention used across this platform's
 * `.env.production.example` files (`replace-with-...`, `must-match-...`,
 * shared `12345678`/`change-me` DB passwords) — distinct from
 * DEV_DEFAULT_CLIENT_SECRETS above, which only covers this file's own
 * original scaffold defaults. An operator who copies an example file and
 * forgets to fill in a value would otherwise boot cleanly in production
 * with a guessable, publicly-documented secret.
 */
const PLACEHOLDER_PATTERNS = [/^replace-with-/i, /^must-match-/i, /change-me/i, /^12345678$/];
function looksLikePlaceholder(value: string | undefined | null): boolean {
  if (!value) return false;
  return PLACEHOLDER_PATTERNS.some((re) => re.test(value));
}

function assertProdSafeDefaults(): void {
  if (!isProd) return;
  const problems: string[] = [];
  for (const c of IDP_CONFIG.clientSeed) {
    if (DEV_DEFAULT_CLIENT_SECRETS.includes(c.client_secret))
      problems.push(
        `client_secret for "${c.client_id}" is still the dev default`,
      );
    if (looksLikePlaceholder(c.client_secret))
      problems.push(
        `client_secret for "${c.client_id}" still looks like an unfilled .env.production.example placeholder`,
      );
  }
  if (IDP_CONFIG.databaseUrl.includes(":change-me@"))
    problems.push("DATABASE_URL still uses the dev placeholder password");
  // NOTE (2026-07-31, explicit user decision): idpprod intentionally shares the
  // same 12345678 password as gmsprod/dmsprod/mrm (see root CLAUDE.md). C6's
  // hard boot-refuse on that password was relaxed back down to "documented,
  // not enforced" for this DB — do not re-add without checking with the user
  // first, since the deploy guide still recommends rotating it.
  if (IDP_CONFIG.cookieKeys.some((k) => k.startsWith("dev-cookie-key") || looksLikePlaceholder(k)))
    problems.push("COOKIE_KEYS still uses the dev placeholder keys");
  if (
    IDP_CONFIG.totpEncryptionKey === "dev-only-totp-key-do-not-use-in-prod" ||
    looksLikePlaceholder(IDP_CONFIG.totpEncryptionKey)
  )
    problems.push(
      "TOTP_ENCRYPTION_KEY still uses the dev/example placeholder — every stored TOTP secret would be decryptable",
    );
  if (
    IDP_CONFIG.auditHmacSecret === "dev-only-audit-hmac-secret-do-not-use-in-prod" ||
    looksLikePlaceholder(IDP_CONFIG.auditHmacSecret)
  )
    problems.push(
      "IDP_AUDIT_HMAC_SECRET still uses the dev/example placeholder — the admin-audit hash chain would be forgeable by anyone who knows this source file",
    );
  if (IDP_CONFIG.gms.enabled && !IDP_CONFIG.gms.internalApiKey) {
    problems.push(
      "GMS_INTERNAL_API_KEY is required when the GMS bridge is enabled",
    );
  }
  if (IDP_CONFIG.gms.enabled && looksLikePlaceholder(IDP_CONFIG.gms.internalApiKey)) {
    problems.push("GMS_INTERNAL_API_KEY still looks like an unfilled placeholder");
  }
  if (IDP_CONFIG.gms.enabled && looksLikePlaceholder(IDP_CONFIG.gms.rolesApiKey)) {
    problems.push("SSO_ROLES_API_KEY still looks like an unfilled placeholder");
  }
  if (looksLikePlaceholder(IDP_CONFIG.dmsInternalApiKey)) {
    problems.push("DMS_INTERNAL_API_KEY still looks like an unfilled placeholder");
  }
  if (
    IDP_CONFIG.gms.enabled &&
    /gms\.localtest\.me/.test(IDP_CONFIG.gateway.publicUrl)
  ) {
    problems.push(
      "GATEWAY_URL is still the dev-only gms.localtest.me address — set it to the real nginx-routed production URL (e.g. https://<host>/gms/__sso's origin) or the GMS SSO tile's post-handoff redirect will not resolve for real users",
    );
  }
  // Browser-facing URLs only — the ones rendered as a clickable redirect
  // target for a real user's browser (portal app tiles). Deliberately
  // excludes dms.apiBaseUrl/dms.backchannelLogoutUri/gms.apiBase: those are
  // server-to-server calls SSO's own backend makes directly (admin console
  // internal-API calls, backchannel logout POSTs, the GMS bridge), and on
  // this platform's actual single-host topology (root CLAUDE.md — one
  // internal server behind one nginx reverse proxy) they are CORRECTLY 127.0.0.1/loopback
  // in production, not a bug — guarding them here broke a real local-prod
  // boot on 2026-08-07 (SSO_API_BASE/GMS_API_BASE/DMS_API_BASE_URL are all
  // loopback by design in .env.production). gms.frontendUrl is excluded too:
  // it's dead config, never read anywhere outside this file.
  const urlsToCheck: Array<[string, string | undefined]> = [
    ["DMS_OIDC_AUTHORIZE_URL", IDP_CONFIG.dms.authorizeUrl],
    ["MRS_SSO_LOGIN_URL", IDP_CONFIG.mrs.loginUrl],
  ];
  for (const [name, value] of urlsToCheck) {
    if (value && LOOPBACK_HOST_RE.test(value)) {
      problems.push(`${name} still resolves to a dev localhost URL (${value}) — set it to the real nginx-routed production URL`);
    }
  }
  for (const client of IDP_CONFIG.clientSeed) {
    for (const uri of [...client.redirect_uris, ...client.post_logout_redirect_uris]) {
      if (LOOPBACK_HOST_RE.test(uri)) {
        problems.push(`clientSeed "${client.client_id}" still has a dev localhost URI (${uri}) in redirect_uris/post_logout_redirect_uris`);
      }
    }
  }
  if (problems.length > 0) {
    throw new Error(
      `Refusing to start in production with insecure defaults:\n  - ${problems.join("\n  - ")}`,
    );
  }
}
assertProdSafeDefaults();

/** Redacts the password out of a postgres connection string for safe logging. */
function redactDbUrl(url: string): string {
  return url.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:***@");
}

/**
 * Mirror image of assertProdSafeDefaults(): catches a DEV process that has
 * somehow resolved a production-looking resource — the exact failure mode
 * documented in root CLAUDE.md's "Known footguns" (a machine-wide
 * DATABASE_URL/other env var silently winning over this service's own
 * `.env`). `dotenv.config({ override: true })` above already fixes that for
 * this process's OWN env loading, but this is a loud, independent backstop:
 * if it ever fires, `npm run dev` is about to read/write the real prod DB or
 * mint tokens under the real prod issuer instead of the local dev ones — the
 * exact "signing out and back in lands on prod" failure mode is silent
 * corruption of someone else's live session state, so this must throw, not
 * warn.
 */
function assertDevSafeDefaults(): void {
  if (isProd) return;
  const problems: string[] = [];
  if (/idpprod|rlwy\.net|railway\.app|amazonaws\.com/i.test(IDP_CONFIG.databaseUrl)) {
    problems.push(
      `DATABASE_URL resolves to a production-looking host/db (${redactDbUrl(IDP_CONFIG.databaseUrl)}) while NODE_ENV is not "production" — check for a machine-wide DATABASE_URL env var shadowing this service's own .env`,
    );
  }
  if (/examplecorp\.co(m)?$|examplecorp\.co\//i.test(issuerUrl.replace(/^https?:\/\//, ""))) {
    problems.push(
      `IDP_ISSUER ("${issuerUrl}") looks like the real production domain while running in dev mode — this would mint tokens and cookies for the live IdP instead of a local one`,
    );
  }
  if (problems.length > 0) {
    throw new Error(
      `Refusing to start in dev mode against production-looking resources:\n  - ${problems.join("\n  - ")}`,
    );
  }
}
assertDevSafeDefaults();
