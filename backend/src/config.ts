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

import fs from "node:fs";
import path from "node:path";
import dotenv from "dotenv";
import { parseLicenseEnforcement, parseLicenseRequired } from "./licenses/enforcement.js";
import { parseOwnerAuthenticatorRequired, parseOwnerVerificationRequired } from "./owner/policy.js";
import { parseProductClients } from "./oidc/product-clients.js";

// ---------------------------------------------------------------------------
// ENV FILE LOADING CONTRACT — kept identical between SSO and DMS (each's own
// config.ts/env.ts). GMS is a deliberate exception (it is the reference implementation for env
// loading on this platform and is not to be changed) —
// it achieves the same practical isolation through its own native
// `['.env', '.env.<nodeEnv>']` layering instead of this file's explicit
// per-mode branches, so don't expect byte-identical code there.
//
//   NODE_ENV=production   ->  .env.production ONLY. `.env`/`.env.development` NEVER read.
//   NODE_ENV=mirror        ->  .env.mirror ONLY. A third, fully isolated
//                              environment — local production-parity, never
//                              shared secrets/DBs with dev or real prod.
//   anything else          ->  .env.development if present, else bare `.env`.
//
// Production (and mirror) are deliberately ISOLATED rather than layered.
// `.env` used to be loaded underneath `.env.production` in production, which
// looks harmless and is not: dotenv only overrides the keys the layering file
// actually NAMES, so every key `.env.production` happens not to mention
// silently keeps its DEVELOPER value. For this service that was ten keys —
// the whole LDAP/AD block and the token TTLs — quietly sourced from the dev
// file on a production box.
//
// SSO is the worst of the three systems to get this wrong in, for a reason
// worth stating: `env()` has a fallback for EVERY variable, so SSO never
// fails to boot on missing configuration. It boots happily on dev defaults
// instead. A wrong DMS config is loud; a wrong SSO config is silent, and SSO
// is the front door to every system on the platform.
//
// NODE_ENV is read from the real process environment BEFORE any file is
// loaded, so no env file can influence which env file gets loaded. (The dev
// `.env` sets NODE_ENV=development on its first line; loaded with
// override:true it used to clobber the launcher's NODE_ENV=production, which
// is exactly the fault this ordering prevents.) The `*:prod` npm scripts set
// it via scripts/run-with-env.cjs rather than shell-specific syntax.
// ---------------------------------------------------------------------------
const externalNodeEnv = process.env.NODE_ENV;
let baseEnvLoad: ReturnType<typeof dotenv.config> | undefined;
let prodEnvLoad: ReturnType<typeof dotenv.config> | undefined;

if (externalNodeEnv === "production") {
  const productionEnvPath = path.resolve(process.cwd(), ".env.production");
  if (!fs.existsSync(productionEnvPath)) {
    // dotenv is a SILENT no-op on a missing file, and because every env()
    // call here has a fallback, SSO would otherwise start normally on the
    // full set of DEVELOPMENT defaults: the `idp` dev database, dev client
    // secrets, and a localhost issuer baked into every token it signs.
    // Nothing downstream would report a problem. Refuse instead.
    throw new Error(
      `NODE_ENV=production but ${productionEnvPath} does not exist.\n` +
        "Production configuration is read from .env.production ONLY — `.env` is the development " +
        "file and is deliberately not read in production.\n" +
        ".env.production is gitignored (it holds real secrets) so it is never part of a clone or a " +
        "file copy: it has to be placed on this machine by hand.",
    );
  }
  // override:true so this file wins over any inherited shell/global var
  // (e.g. a machine-wide DATABASE_URL pointing elsewhere).
  prodEnvLoad = dotenv.config({ path: productionEnvPath, override: true });
  // .env.production sets NODE_ENV=production itself; pin it anyway so the file
  // and the launcher can never disagree about which mode this process is in.
  process.env.NODE_ENV = "production";
} else if (externalNodeEnv === "mirror") {
  // A genuinely separate third environment — a local production-parity
  // "mirror" for verifying prod-shaped behavior without touching the real
  // dev `.env` or the real `.env.production`. Same isolation contract as
  // production: this file ONLY, never layered under `.env`.
  const mirrorEnvPath = path.resolve(process.cwd(), ".env.mirror");
  if (!fs.existsSync(mirrorEnvPath)) {
    throw new Error(
      `NODE_ENV=mirror but ${mirrorEnvPath} does not exist.\n` +
        "Mirror configuration is read from .env.mirror ONLY — `.env`/`.env.development` is the " +
        "development file and `.env.production` is the real production file; neither is read here.",
    );
  }
  prodEnvLoad = dotenv.config({ path: mirrorEnvPath, override: true });
  process.env.NODE_ENV = "mirror";
} else {
  // Prefer .env.development when present (matches DMS's config/env.ts and
  // the frontends' existing convention); fall back to bare `.env` for a
  // checkout that has never been given the split-file treatment.
  const developmentEnvPath = path.resolve(process.cwd(), ".env.development");
  const devEnvPath = fs.existsSync(developmentEnvPath)
    ? developmentEnvPath
    : path.resolve(process.cwd(), ".env");
  baseEnvLoad = dotenv.config({ path: devEnvPath, override: true });
  if (externalNodeEnv) {
    process.env.NODE_ENV = externalNodeEnv;
  }
}

/**
 * override:true above only protects us when THIS service's own env file
 * actually defines DATABASE_URL — dotenv only overrides keys present in the
 * loaded file, so a stray/machine-wide DATABASE_URL from the shell environment
 * still wins silently if that line is ever missing, blank, or commented out (a
 * fresh checkout, a bad merge, someone debugging). This exact footgun has
 * already bitten this platform more than once (MRS needed two separate
 * fixes for it). Refuse to boot on an
 * ambient DATABASE_URL the loaded env file did not define, unless
 * DATABASE_URL_TRUSTED=1 explicitly says that's expected.
 *
 * Exactly one of baseEnvLoad/prodEnvLoad is set, per the contract above, so
 * this reads whichever file was actually loaded.
 */
if (
  process.env.DATABASE_URL &&
  !baseEnvLoad?.parsed?.DATABASE_URL &&
  !prodEnvLoad?.parsed?.DATABASE_URL &&
  process.env.DATABASE_URL_TRUSTED !== "1"
) {
  throw new Error(
    "DATABASE_URL is set in the environment but not defined in " +
      (externalNodeEnv === "production"
        ? "this service's .env.production (the only env file read in production)"
        : "this service's .env") +
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
  if (v === undefined || v === "") return fallback;
  const n = Number(v);
  // "1h" for a seconds setting used to become NaN and silently disable the behaviour it configured.
  if (!Number.isFinite(n) || n < 0) throw new Error(`${name} must be a non-negative number, got "${v}"`);
  return n;
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
 * to portal.examplecorp.com/portal (Apache 404) instead of .../sso/portal. One
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
];

/** Extra applications from PRODUCT_CLIENTS_JSON, parsed once (a malformed list stops the start; oidc/product-clients.ts). */
const PRODUCT_CLIENT_LIST = parseProductClients(process.env.PRODUCT_CLIENTS_JSON);

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
   * P1-10: source addresses allowed to reach SSO's INBOUND internal API
   * (/internal/gms, /api/v1/internal/gms), checked before the shared key is
   * compared. Every real caller is the GMS backend on this host, so loopback-only
   * is the actual topology rather than a restriction. `*` disables the check.
   */
  internalApiAllowedIps: env("INTERNAL_API_ALLOWED_IPS", "127.0.0.1,::1,::ffff:127.0.0.1"),

  metrics: {
    /**
     * P1-20. `/metrics` and `/api/v1/metrics` report MFA-enrolment counts and
     * hourly login-FAILURE counts, which together tell an attacker how big the
     * un-MFA'd population is and whether their own attempts are registering.
     * They were open to anyone who could reach the port. Closed by default now;
     * GMS has had exactly this flag (app.config.ts) all along.
     */
    publicRouteEnabled: env("ENABLE_PUBLIC_METRICS_ROUTE", "false") === "true",
    /** Presented as `x-metrics-key`, for a scraper with no admin session. */
    apiKey: process.env.METRICS_API_KEY ?? "",
  },
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
   * Interface to bind. Loopback by default, per the pre-deploy
   * rule ("All 4 API ports loopback-only: 7100/7200/7300/7400 …
   * Nothing on 0.0.0.0") and the platform's stated
   * architecture: Apache on 80/443 is the ONLY sanctioned public entry point.
   *
   * This service previously passed no host to app.listen() at all, which means
   * Node binds 0.0.0.0 — so 7300 (and the gateway's 4200) were reachable from
   * anywhere on the LAN, bypassing Apache and TLS entirely. That contradicted
   * C5 while C5 was being ticked off, with only the host firewall's default
   * inbound deny actually standing in the way. Override via HOST only for a
   * genuine multi-host topology.
   */
  host: process.env.HOST ?? "127.0.0.1",

  /**
   * Postgres connection for the IdP's OWN store (oidc artifacts + users/roles/clients).
   * Separate database (`idp`) on the shared local PG server — apps never share a DB.
   */
  databaseUrl: env(
    "DATABASE_URL",
    "postgres://postgres:change-me@localhost:5432/idp",
  ),

  /**
   * Postgres pool limits. Explicit rather than pg's defaults because this pool
   * serves `findAccount`, which runs on every token issuance for every client —
   * see the note in db/pool.ts for what each of these prevents.
   */
  db: {
    poolMax: envInt("DB_POOL_MAX", 20),
    connectionTimeoutMs: envInt("DB_CONNECTION_TIMEOUT_MS", 5000),
    idleTimeoutMs: envInt("DB_IDLE_TIMEOUT_MS", 30000),
    statementTimeoutMs: envInt("DB_STATEMENT_TIMEOUT_MS", 15000),
  },

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
  /** Refuse the admin console to administrators who have not enrolled two-factor sign-in (default off; see requireAdmin.ts). */
  adminRequireMfa: env("ADMIN_REQUIRE_MFA", "false").toLowerCase() === "true",

  trustProxyHops: envInt("TRUST_PROXY_HOPS", 1),

  /**
   * Platform licensing (docs/operations/PLATFORM-LICENSING.md): `enforce` (default), `warn` (compute and report, never block) or `off`.
   * With no licence row for SSO, none of this has any effect. `LICENSE_ENFORCEMENT=warn` is the emergency switch.
   */
  licenseEnforcement: parseLicenseEnforcement(process.env.LICENSE_ENFORCEMENT).mode,
  licenseEnforcementInvalid: parseLicenseEnforcement(process.env.LICENSE_ENFORCEMENT).invalid,
  /** Per-application entitlement (docs/operations/PLATFORM-LICENSING.md section 9): true in production unless the environment says otherwise. */
  licenseRequired: parseLicenseRequired(process.env.LICENSE_REQUIRED, isProd).required,
  licenseRequiredExplicit: parseLicenseRequired(process.env.LICENSE_REQUIRED, isProd).explicit,
  /** Path to a dedicated licence-signing PEM private key kept OUTSIDE the repository. Unset: licences are signed with the OIDC key (development only). */
  licenseSigningKeyFile: (process.env.LICENSE_SIGNING_KEY_FILE ?? "").trim(),

  /**
   * Owner verification (docs/sso/SSO-OPERATIONS.md, "Owner verification"): a per-operation, server-side check that whoever uses the platform administrator's
   * session is the owner (security questions, emailed code or recovery code, authenticator). OWNER_VERIFICATION_REQUIRED defaults to true in production,
   * the mirror and any non-local issuer, false in development and tests. Required and not enrolled = owner-only operations are REFUSED (OWNER_NOT_ENROLLED).
   * OWNER_STORE_KEY_FILE: the AES key file for the sealed owner store, outside the repository (created by "npm run owner:enroll"). The owner's mailbox address and
   * every secret live only in that sealed store, never in an env file. SMTP_* send the emailed code; if they are unset or changed the emailed code is unavailable
   * and an offline recovery code takes its place (never fewer factors).
   */
  ownerVerificationRequired: parseOwnerVerificationRequired(process.env.OWNER_VERIFICATION_REQUIRED, NODE_ENV, isProd).required,
  ownerVerificationRequiredExplicit: parseOwnerVerificationRequired(process.env.OWNER_VERIFICATION_REQUIRED, NODE_ENV, isProd).explicit,
  ownerStoreKeyFile: (process.env.OWNER_STORE_KEY_FILE ?? "").trim(),
  /**
   * OWNER_AUTHENTICATOR_REQUIRED (default false, owner decision 2026-10-21; only the word true turns it on): whether a NEW owner enrolment (owner:enroll / owner:recover) includes the phone authenticator. With false (the default) the
   * owner proves themselves with the security questions and the emailed code (or one recovery code). It only decides what a new enrolment asks for: the factors
   * of an enrolment are recorded inside the sealed owner store and verification always demands those, so changing this later never weakens an existing one.
   */
  ownerAuthenticatorRequired: parseOwnerAuthenticatorRequired(process.env.OWNER_AUTHENTICATOR_REQUIRED).required,
  ownerAuthenticatorRequiredExplicit: parseOwnerAuthenticatorRequired(process.env.OWNER_AUTHENTICATOR_REQUIRED).explicit,
  smtp: {
    host: (process.env.SMTP_HOST ?? "").trim(),
    port: envInt("SMTP_PORT", 587),
    secure: (process.env.SMTP_SECURE ?? "").trim().toLowerCase() === "true",
    user: (process.env.SMTP_USER ?? "").trim(),
    pass: process.env.SMTP_PASS ?? "",
    from: (process.env.SMTP_FROM ?? "").trim(),
  },

  /**
   * Incident containment (docs: SSO-OPERATIONS.md, "Tamper detection and incident response"). INCIDENT_LOCK_FILE: while this file exists every
   * state-changing request is refused 403 INCIDENT_READ_ONLY (ops/incidentLock.ts); unset = off. INCIDENT_RESPONSE: `contain` (record, alert, revoke the
   * offending actor's sessions, lock) | `alert` (record and alert only) | `off` (detectors silent). Default: contain in production, alert elsewhere,
   * so development is never locked unless someone switches it on.
   */
  incidentLockFile: (process.env.INCIDENT_LOCK_FILE ?? "").trim(),
  incidentResponse: ((): "contain" | "alert" | "off" => {
    const v = (process.env.INCIDENT_RESPONSE ?? "").trim().toLowerCase();
    return v === "contain" || v === "alert" || v === "off" ? v : isProd ? "contain" : "alert";
  })(),
  /** Shared-secret file for the read-only chain-head endpoint the tamper watcher calls (ops/chainHead). Unset = that endpoint answers 404. */
  opsWatchKeyFile: (process.env.OPS_WATCH_KEY_FILE ?? "").trim(),

  /**
   * How many password checks (scrypt, ~128 MB and a fraction of a second each) may run at once, how many may wait, and how long one
   * may wait before it is turned away with "busy, try again". Without a bound, a flood of sign-in attempts from many addresses
   * queues unlimited scrypt jobs on libuv's small thread pool (shared with DNS lookups and file access), exhausting memory and
   * slowing the token endpoint every system depends on. See infrastructure/workGate.ts. Worst-case memory is
   * concurrency x 128 MB; UV_THREADPOOL_SIZE (set by the supervised start scripts) leaves threads free for everything else.
   */
  passwordHash: {
    concurrency: envInt("PASSWORD_HASH_CONCURRENCY", 3),
    maxQueue: envInt("PASSWORD_HASH_QUEUE", 60),
    maxWaitMs: envInt("PASSWORD_HASH_WAIT_MS", 8000),
  },

  /**
   * Password lockout (5 failures -> locked for 15 minutes, plus the per-IP ceiling). The owner's
   * decision 2026-10-09 is OFF: a person may retry as often as they like, and every failure is
   * still recorded in idp_login_events and shown on the Sign-ins page. Set LOGIN_LOCKOUT_ENABLED=true
   * to bring the lock back. The authenticator-code (MFA) lockout is separate and always on.
   */
  loginLockoutEnabled: env("LOGIN_LOCKOUT_ENABLED", "false").toLowerCase() === "true",

  /**
   * Secret that turns the platform administrator's real email into the keyed
   * pseudonym the database stores instead (auth/platform-admin.ts). Needed at
   * RUNTIME only so the real email typed at the login form can be mapped to
   * that pseudonym; with it unset the account is stored and matched by its real
   * email (weaker: the database then names the owner). Generate once, long and
   * random, and never change it afterwards: changing it orphans the account.
   */
  platformAdminPepper: env("PLATFORM_ADMIN_PEPPER", ""),

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
   * Dev defaults use bare localhost ports (no Apache). Prod is reached through
   * the shared Apache edge via `/dms` path prefix.
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
    /**
     * Hard ceiling on every server-side call into DMS's internal API
     * (admin/dms-internal-client.ts). Load-bearing rather than a nicety: the
     * role-resolution call on this client runs inside `findAccount`, which
     * oidc-provider invokes on every token issuance for every client — so an
     * unbounded wait here turns a DMS hang into a platform-wide login stall.
     * Short by design; callers degrade gracefully on timeout.
     */
    internalTimeoutMs: envInt("DMS_INTERNAL_TIMEOUT_MS", 4000),
  },
  /**
   * The applications besides DMS and GMS that are told, server to server, when a person's SSO session ends (auth/logout-notify.ts): MOS (when MOS_ENABLED=true and
   * MOS_BACKCHANNEL_LOGOUT_URI is set) and every PRODUCT_CLIENTS_JSON entry that has a backchannel_logout_uri. Empty when none is configured.
   */
  appLogoutTargets: [
    ...(process.env.MOS_ENABLED === "true" && (process.env.MOS_BACKCHANNEL_LOGOUT_URI ?? "").trim()
      ? [{ client_id: "mos", uri: (process.env.MOS_BACKCHANNEL_LOGOUT_URI ?? "").trim() }]
      : []),
    ...PRODUCT_CLIENT_LIST.filter((c) => c.backchannel_logout_uri).map((c) => ({ client_id: c.client_id, uri: c.backchannel_logout_uri as string })),
  ] as Array<{ client_id: string; uri: string }>,
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
    /**
     * P2-5: kept, but the comment that claimed the bridge landing page uses it to
     * "seed its session" was wrong — nothing outside this file reads it, as
     * assertProdSafeDefaults's own exclusion note already observed.
     *
     * NOT deleted, deliberately: GMS_FRONTEND_URL is set in four committed env
     * files including .env.production, so removing the config key would leave
     * four dangling entries and make the next reader wonder which side is stale.
     * It is documented dead weight now instead of undocumented dead weight — a
     * one-line removal here plus four env edits is a separate, deliberate
     * cleanup, not something to fold into an audit fix.
     */
    frontendUrl: process.env.GMS_FRONTEND_URL ?? "http://localhost:7201",
    /** GMS backend API base, for optional server-side calls. */
    apiBase: process.env.GMS_API_BASE ?? "http://localhost:7200/api/v1",
    /** GMS SPA localStorage key (Zustand persist). */
    sessionStorageKey: process.env.GMS_SESSION_KEY ?? "gms-auth-session",
    /**
     * Hard ceiling on server-side calls into GMS's internal admin API
     * (admin/gms-internal-client.ts — listGmsOffices/getGmsUserStatus).
     * Previously unset entirely (no timeout at all, Finding 6); this default
     * sits between dms.internalTimeoutMs (4000ms) and the login-bridge's
     * gmsRequest() (8000ms) since this path is admin-console-only, not on the
     * token-issuance critical path.
     */
    internalTimeoutMs: envInt("GMS_INTERNAL_TIMEOUT_MS", 6000),
    /**
     * Inbound direction: gates GMS calling INTO SSO's per-user role-grant API
     * (directive §6.3). Same shared-secret-name-on-both-sides convention as
     * DMS_INTERNAL_API_KEY — GMS presents this value, SSO checks it here.
     */
    rolesApiKey: process.env.SSO_ROLES_API_KEY ?? "",
  },

  /**
   * Same-origin reverse-proxy gateway for the GMS SPA (closes the cross-origin
   * handoff). Served on a non-loopback host that resolves to 127.0.0.1 so the
   * GMS frontend honors a same-origin API base (its dev code force-routes to
   * :5000 only for literal localhost/127.0.0.1 hosts).
   */
  gateway: {
    port: envInt("GATEWAY_PORT", 4200),
    /** Requests per minute per address through the gateway (every page, asset and API call to GMS passes it). */
    rateLimitPerMinute: envInt("GATEWAY_RATE_LIMIT_PER_MINUTE", 6000),
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
      // P1-2. `edams_roles` is DMS's own client-scoped role claim; it must NOT
      // include `gms_roles`. `ad_groups` stays because DMS's idp_role_mappings
      // fallback reads it (auth.routes.ts). Keep in step with migration 012 and
      // with DMS's OIDC_SCOPES — a scope DMS requests but is not allowed here
      // fails authorize outright, and one it is allowed but does not request is
      // simply absent from the id_token.
      scope: "openid profile email ad_groups edams_roles",
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
      // P1-2. `gms_roles` only — the GMS bridge has no business receiving DMS's
      // role names. `ad_groups` is required: bridge/gms.ts maps AD groups to the
      // GMS role set when minting the GMS session.
      scope: "openid profile email ad_groups gms_roles",
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
      // P1-2. The launcher needs the AD group list (entitlements + the admin
      // tile) and nothing else — no relying party's roles at all.
      scope: "openid profile email ad_groups",
      redirect_uris: [
        `${env("IDP_ISSUER", "http://localhost:7301").replace(/\/$/, "")}/portal/callback`,
      ],
      name: "Example Corp SSO Portal",
      post_logout_redirect_uris: [
        `${env("IDP_ISSUER", "http://localhost:7301").replace(/\/$/, "")}/portal`,
      ],
    },
    // MOS (Manufacturing Operations Suite, on Odoo) signs in through this IdP. Registered ONLY when MOS_ENABLED=true, and
    // then with no fallbacks: a secret or address that is missing is a startup error, so a production IdP can never boot
    // with a seeded client that still holds a development secret or a localhost address (assertProdSafeDefaults).
    // MOS is a standalone product: it has no app-access entry; its portal tile (portal/catalog.ts) appears only when MOS_PORTAL_URL is set.
    ...(process.env.MOS_ENABLED === "true"
      ? [
          {
            client_id: "mos",
            client_secret: env("MOS_CLIENT_SECRET"),
            scope: "openid profile email",
            redirect_uris: env("MOS_REDIRECT_URIS").split(","),
            name: "MOS (Odoo)",
            post_logout_redirect_uris: env("MOS_LOGOUT_URIS").split(","),
          },
        ]
      : []),
    // Other applications that sign in through this IdP (oidc/product-clients.ts): PRODUCT_CLIENTS_JSON is a JSON list of
    // {client_id, client_secret, redirect_uris, post_logout_redirect_uris, name}; absent or empty means none. Same rule as MOS:
    // every secret and address comes from the environment, none has a default, and a malformed list stops the start.
    ...PRODUCT_CLIENT_LIST.map(({ backchannel_logout_uri: _backchannel, ...client }) => client),
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
 * shared `a well-known weak password`/`change-me` DB passwords) — distinct from
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
  // Added 2026-10-10 (security audit): settings whose comments say "never in production" are now refused there.
  if (IDP_CONFIG.internalApiAllowedIps.split(",").map((x) => x.trim()).includes("*"))
    problems.push("INTERNAL_API_ALLOWED_IPS=* opens the internal GMS endpoints to every address");
  if (IDP_CONFIG.ldap.url && !/^ldaps:\/\//i.test(IDP_CONFIG.ldap.url))
    problems.push("LDAP_URL must use ldaps:// - with ldap:// every AD sign-in sends the person's password in clear text");
  if (IDP_CONFIG.cookieKeys.some((k) => k.length < 16))
    problems.push("COOKIE_KEYS entries must be at least 16 characters (they sign every session cookie)");
  if (IDP_CONFIG.totpEncryptionKey.length < 16)
    problems.push("TOTP_ENCRYPTION_KEY must be at least 16 characters");
  if (IDP_CONFIG.auditHmacSecret.length < 16)
    problems.push("IDP_AUDIT_HMAC_SECRET must be at least 16 characters");
  // NOTE (2026-07-31, explicit user decision): idpprod intentionally shares the
  // same a well-known weak password password as gmsprod/dmsprod/mrm. The
  // hard boot-refuse on that password (pre-deploy check C6) was relaxed back down to "documented,
  // not enforced" for this DB — do not re-add without checking with the user
  // first, since rotating it is still recommended.
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
      "GATEWAY_URL is still the dev-only gms.localtest.me address — set it to the real Apache-routed production URL (e.g. https://<host>/gms/__sso's origin) or the GMS SSO tile's post-handoff redirect will not resolve for real users",
    );
  }
  // Browser-facing URLs only — the ones rendered as a clickable redirect
  // target for a real user's browser (portal app tiles). Deliberately
  // excludes dms.apiBaseUrl/dms.backchannelLogoutUri/gms.apiBase: those are
  // server-to-server calls SSO's own backend makes directly (admin console
  // internal-API calls, backchannel logout POSTs, the GMS bridge), and on
  // this platform's actual single-host topology (one
  // internal server behind one Apache) they are CORRECTLY 127.0.0.1/loopback
  // in production, not a bug — guarding them here broke a real local-prod
  // boot on 2026-08-07 (SSO_API_BASE/GMS_API_BASE/DMS_API_BASE_URL are all
  // loopback by design in .env.production). gms.frontendUrl is excluded too:
  // it's dead config, never read anywhere outside this file.
  // Skip the localhost-URL checks under NODE_ENV=mirror. The mirror
  // deliberately runs entirely on this one machine — there is no public
  // DNS name it could use instead, so every browser-facing URL (issuer,
  // redirect_uris, DMS_OIDC_AUTHORIZE_URL) is loopback by inherent, correct
  // topology, not by neglect. That is exactly the reasoning the comment
  // above already gives for why server-to-server loopback calls are exempt
  // in real production; a local mirror's BROWSER-facing calls are loopback
  // for the identical reason (this "browser" is also on this machine). Real
  // dev (isProd false here, so this function already returned above) and
  // real production (NODE_ENV=production, genuinely must not be localhost)
  // still get the full check.
  if (NODE_ENV !== "mirror") {
    const urlsToCheck: Array<[string, string | undefined]> = [
      ["DMS_OIDC_AUTHORIZE_URL", IDP_CONFIG.dms.authorizeUrl],
    ];
    for (const [name, value] of urlsToCheck) {
      if (value && LOOPBACK_HOST_RE.test(value)) {
        problems.push(`${name} still resolves to a dev localhost URL (${value}) — set it to the real Apache-routed production URL`);
      }
    }
    for (const client of IDP_CONFIG.clientSeed) {
      for (const uri of [...client.redirect_uris, ...client.post_logout_redirect_uris]) {
        if (LOOPBACK_HOST_RE.test(uri)) {
          problems.push(`clientSeed "${client.client_id}" still has a dev localhost URI (${uri}) in redirect_uris/post_logout_redirect_uris`);
        }
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
 * known on this platform as a footgun (a machine-wide
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
  // Skip the prod-looking-name check under NODE_ENV=mirror: the mirror
  // deliberately connects to a database literally named idpprod (per
  // explicit platform decision — the mirror runs against the exact same
  // db/user identity real production does, on a local Postgres instance the
  // real server can never reach), so "looks like idpprod" is expected here,
  // not a leak. Real dev (externalNodeEnv anything else, isProd still false)
  // still gets the full check — this is what would have caught an
  // accidental machine-wide DATABASE_URL pointing a genuine dev session at
  // idpprod.
  if (externalNodeEnv !== "mirror" && /idpprod|rlwy\.net|railway\.app|amazonaws\.com/i.test(IDP_CONFIG.databaseUrl)) {
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
