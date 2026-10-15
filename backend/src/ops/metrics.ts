/**
 * Operational counters — ONE implementation, and an access gate (P1-20).
 *
 * Two problems this file exists to fix.
 *
 * 1. The counters were UNAUTHENTICATED, on both `/metrics` and
 *    `/api/v1/metrics`. Between them they report how many accounts exist, how
 *    many are active, **how many have MFA enrolled** (therefore how many do
 *    not), live SSO/portal/gateway session counts, and hourly login-attempt and
 *    login-FAILURE counts. That last pair is the useful one for an attacker: it
 *    tells them whether their own attempts are landing, and the MFA figure tells
 *    them how large the un-MFA'd population is. GMS already gates its equivalent
 *    behind ENABLE_PUBLIC_METRICS_ROUTE; SSO — the identity provider for the
 *    whole platform — gated nothing.
 *
 * 2. The same ten-line SQL block existed twice, in main.ts and in
 *    api/v1/platform.router.ts, and the two error paths had already drifted:
 *    main.ts's had been fixed to stop returning `(err as Error).message`, and
 *    platform.router.ts's still handed the raw Postgres error — host, database
 *    name and role — to an unauthenticated caller. Two copies is how one gets
 *    fixed and the other does not, which is exactly what happened here.
 */

import crypto from 'node:crypto';
import type { Request } from 'express';
import { IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { getPortalSession, type PortalSession } from '../portal/session.js';
import { undecryptableSecretCount } from '../auth/totp.js';

const METRICS_SQL = `SELECT
   (SELECT COUNT(*) FROM idp_users WHERE NOT is_platform_admin) AS users_total,
   (SELECT COUNT(*) FROM idp_users WHERE is_active AND NOT is_platform_admin) AS users_active,
   (SELECT COUNT(*) FROM idp_users WHERE totp_enabled AND NOT is_platform_admin) AS users_mfa_enrolled,
   (SELECT COUNT(*) FROM oidc_artifacts WHERE kind = 'Session' AND payload->>'accountId' IS NOT NULL AND payload->>'accountId' NOT IN (SELECT id::text FROM idp_users WHERE is_platform_admin) AND (expires_at IS NULL OR expires_at > NOW())) AS sessions_sso_active,
   (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'portal' AND coalesce(payload->>'accountId', '') NOT IN (SELECT id::text FROM idp_users WHERE is_platform_admin) AND expires_at > NOW()) AS sessions_portal_active,
   (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'gateway' AND expires_at > NOW()) AS sessions_gateway_active,
   (SELECT COUNT(*) FROM idp_login_events WHERE created_at > NOW() - INTERVAL '1 hour') AS logins_attempted_1h,
   (SELECT COUNT(*) FROM idp_login_events WHERE success = FALSE AND created_at > NOW() - INTERVAL '1 hour') AS logins_failed_1h,
   (SELECT COUNT(*) FROM idp_signing_keys WHERE is_active) AS signing_keys_active`;

/** The single source of these numbers. Throws on DB failure; callers decide what to say. */
export async function collectPlatformMetrics(): Promise<Record<string, number>> {
  const { rows } = await pool.query<Record<string, string>>(METRICS_SQL);
  return {
    ...Object.fromEntries(Object.entries(rows[0] ?? {}).map(([k, v]) => [k, Number(v)])),
    /**
     * P1-4: times a stored TOTP secret failed to decrypt since this process
     * started. Non-zero means TOTP_ENCRYPTION_KEY no longer matches the key the
     * secrets were written with, and every enrolled user is locked out of MFA.
     * Process-lifetime rather than a DB count on purpose — it resets on restart,
     * which is the right semantics for a config-mismatch alarm.
     */
    users_mfa_secret_undecryptable: undecryptableSecretCount(),
  };
}

/** Fixed-length constant-time compare for the scrape key. */
function keyMatches(provided: string, expected: string): boolean {
  const a = crypto.createHash('sha256').update(provided, 'utf8').digest();
  const b = crypto.createHash('sha256').update(expected, 'utf8').digest();
  return crypto.timingSafeEqual(a, b);
}

function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) out.push(decodeURIComponent(part.slice(i + 1).trim()));
  }
  return out;
}

/**
 * Who may read the counters:
 *
 *  - a signed-in admin (the same `idp_portal` session + admin-group membership
 *    the admin console uses), so a human can look at them without provisioning
 *    anything; or
 *  - a caller presenting METRICS_API_KEY as `x-metrics-key`, for a
 *    Prometheus-style scraper that has no session; or
 *  - anyone at all, but ONLY if ENABLE_PUBLIC_METRICS_ROUTE is explicitly turned
 *    on. Defaults to false, mirroring GMS's flag of the same name so the two
 *    systems behave the same way.
 */
export async function metricsAccessAllowed(req: Request): Promise<boolean> {
  if (IDP_CONFIG.metrics.publicRouteEnabled) return true;

  const presentedKey = req.header('x-metrics-key');
  if (presentedKey && IDP_CONFIG.metrics.apiKey && keyMatches(presentedKey, IDP_CONFIG.metrics.apiKey)) {
    return true;
  }

  for (const value of cookieValues(req, 'idp_portal')) {
    const session: PortalSession | undefined = await getPortalSession(value);
    if (session?.groups.includes(IDP_CONFIG.adminGroup)) return true;
  }
  return false;
}
