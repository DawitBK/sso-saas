/**
 * Pre-deploy check: resolve SSO's PRODUCTION configuration exactly the way the
 * real service does, print a secret-safe summary, and run every production
 * safety assertion — WITHOUT starting the IdP, binding port 7300/4200, or
 * touching the database.
 *
 *   npm run env:verify:prod
 *
 * Why this exists as a separate command:
 *
 *   1. SSO is the front door to the whole platform: if it comes up wrong,
 *      nobody can log into anything. It is also the system where a
 *      misconfiguration is QUIETEST, because every value in config.ts has a
 *      development fallback — SSO does not fail to start on missing
 *      configuration, it starts on dev defaults. A wrong DMS config is loud; a
 *      wrong SSO config just issues tokens with a localhost issuer.
 *
 *   2. GMS already had an equivalent (`npm run env:check:prod`) and SSO did
 *      not. GMS's is a static file check that never loads the app; this one
 *      goes through the real loader, so it also proves WHICH FILE won.
 *
 * The production assertions (assertProdSafeDefaults) run on import of the
 * config module, so simply loading it is the test — this script adds the
 * human-readable summary and a clear exit status on top.
 *
 * It never prints a secret. Sensitive values are reported as set/unset with a
 * length, so the output is safe to paste into a deployment log or a chat.
 *
 * Exit status: 0 = safe to start. 1 = do not start; the reason is printed.
 */
import { IDP_CONFIG } from "../src/config.js";

const shown = (value: unknown) =>
  value === undefined || value === null || value === "" ? "(unset)" : String(value);

/** For secrets: prove presence and length without disclosing the value. */
const secret = (value: unknown) =>
  value === undefined || value === null || value === "" ? "(unset)" : `set, ${String(value).length} chars`;

const line = (label: string, value: string) => console.log(`  ${label.padEnd(26)} ${value}`);

console.log("");
console.log("SSO production environment verification");
console.log("=======================================");
console.log("");

if (process.env.NODE_ENV !== "production") {
  console.error(
    `REFUSING TO REPORT: NODE_ENV is "${process.env.NODE_ENV}", not "production".\n` +
      "Run this through the production launcher so the right env file is loaded:\n" +
      "    npm run env:verify:prod\n" +
      "Running the underlying script directly (tsx scripts/verify-prod-env.ts) loads the\n" +
      "DEVELOPMENT .env and would tell you nothing about the production configuration.",
  );
  process.exit(1);
}

console.log("Identity and routing");
line("NODE_ENV", shown(IDP_CONFIG.env));
line("isProd", String(IDP_CONFIG.isProd));
line("issuer", shown(IDP_CONFIG.issuer));
line("publicBasePath", shown(IDP_CONFIG.publicBasePath));
line("host : port", `${IDP_CONFIG.host} : ${IDP_CONFIG.port}`);
line("internalUrl", shown(IDP_CONFIG.internalUrl));
line("trustProxyHops", String(IDP_CONFIG.trustProxyHops));
line("internalApiAllowedIps", shown(IDP_CONFIG.internalApiAllowedIps));
console.log("");

console.log("Database");
try {
  const url = new URL(IDP_CONFIG.databaseUrl);
  line("host : port", `${url.hostname} : ${url.port || "(default)"}`);
  line("database", url.pathname.replace(/^\//, ""));
  line("user", decodeURIComponent(url.username) || "(none)");
  line("password", secret(decodeURIComponent(url.password)));
} catch {
  line("databaseUrl", "(unparseable — check DATABASE_URL)");
}
console.log("");

console.log("Secrets — presence only");
line("cookieKeys", `${IDP_CONFIG.cookieKeys.length} key(s)`);
line("totpEncryptionKey", secret(IDP_CONFIG.totpEncryptionKey));
line("auditHmacSecret", secret(IDP_CONFIG.auditHmacSecret));
console.log("");

console.log("Token lifetimes (seconds)");
line("accessToken / idToken", `${IDP_CONFIG.ttl.accessToken} / ${IDP_CONFIG.ttl.idToken}`);
line("refreshToken", String(IDP_CONFIG.ttl.refreshToken));
line("session", String(IDP_CONFIG.ttl.session));
console.log("");

console.log("Active Directory — empty url means AD is off and login is local-only");
line("ldap.url", shown(IDP_CONFIG.ldap.url) === "(unset)" ? "(unset — AD disabled)" : shown(IDP_CONFIG.ldap.url));
line("ldap.bindDN", secret(IDP_CONFIG.ldap.bindDN));
line("ldap.bindPassword", secret(IDP_CONFIG.ldap.bindPassword));
line("ldap.searchBase", shown(IDP_CONFIG.ldap.searchBase));
line("adminGroup", shown(IDP_CONFIG.adminGroup));
console.log("");

console.log("Relying parties");
line("registered OIDC clients", IDP_CONFIG.clientSeed.map((c: { client_id: string }) => c.client_id).join(", "));
line("DMS enabled", String(IDP_CONFIG.dms.enabled));
line("DMS authorizeUrl", shown(IDP_CONFIG.dms.authorizeUrl));
line("DMS apiBaseUrl", shown(IDP_CONFIG.dms.apiBaseUrl));
line("DMS internal key", secret(IDP_CONFIG.dmsInternalApiKey));
line("GMS bridge enabled", String(IDP_CONFIG.gms.enabled));
line("GMS internal key", secret(IDP_CONFIG.gms.internalApiKey));
console.log("");

console.log("Gateway (the same-origin proxy that carries the GMS handoff)");
line("gateway port", String(IDP_CONFIG.gateway.port));
line("gateway publicUrl", shown(IDP_CONFIG.gateway.publicUrl));
line("GMS frontend target", shown(IDP_CONFIG.gateway.gmsFrontendTarget));
line("GMS api target", shown(IDP_CONFIG.gateway.gmsApiTarget));
console.log("");

// Reaching this line means assertProdSafeDefaults() passed during import —
// it throws on a dev placeholder, a loopback URL left in production config,
// or a missing internal API key.
console.log("All production safety assertions passed.");
console.log("");
console.log("Note: this checks CONFIGURATION only. It does not prove Postgres is reachable");
console.log("or that AD binds — those are verified by the health checks described in");
console.log("docs/sso/SSO-OPERATIONS.md after the service starts.");
