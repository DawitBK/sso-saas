/**
 * Same-origin gateway for GMS (the "router/gateway" role of the IdP, done right).
 *
 * Serves the GMS SPA and its API under ONE origin (gms.localtest.me:4200) so the
 * bridged session can be seeded into the SPA's own localStorage and its API calls
 * are same-origin (no CORS, no GMS code change). GMS's dev frontend force-routes
 * its API to :7200 only for literal localhost hosts, so we use a non-loopback
 * host that resolves to 127.0.0.1 and set NEXT_PUBLIC_API_BASE_URL to this origin.
 *
 *   GET /__sso?code=…   redeem one-time bridge handoff → seed SPA session → /
 *   /api/v1/*           → GMS backend
 *   /*                  → GMS frontend (Next.js), websockets included
 */

import { edgeClientIp } from '../http/client-ip.js';
import express from 'express';
import helmet from 'helmet';
import { createLimiter } from '../infrastructure/rateLimiter.js';
import crypto from 'node:crypto';
import type http from 'node:http';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { IDP_CONFIG } from '../config.js';
import { takeGatewaySession } from '../bridge/session.js';
import { logger } from '../logging/logger.js';

/**
 * Map GMS roles to their SPA landing route (mirrors GMS's getPortalPathForRole).
 *
 * In dev, the gateway proxies GMS's frontend root directly (no base path), so
 * these paths resolve as-is under the gateway's own dev origin. In production
 * the gateway is only reachable at the narrow `/gms/__sso` Apache rule — the
 * rest of `/gms` is served directly by GMS's own already-proven Apache rule,
 * at its `NEXT_PUBLIC_BASE_PATH=/gms` prefix — so the post-handoff redirect
 * must include that prefix or it 404s against the bare root.
 */
function portalPathForRoles(roles: string[]): string {
  const prefix = IDP_CONFIG.isProd ? '/gms' : '';
  if (roles.some((r) => r === 'admin' || r === 'super_admin')) return `${prefix}/admin`;
  if (roles.some((r) => r === 'reception' || r === 'super_reception')) return `${prefix}/reception`;
  if (roles.some((r) => r === 'host' || r === 'super_host')) return `${prefix}/host`;
  if (roles.includes('guest')) return `${prefix}/dashboard`;
  return prefix || '/';
}

/**
 * P1-11. Must match GMS's own appConfig.refreshCookiePath: GMS's API lives at the
 * unprefixed `/api/v1` on the shared origin, and `/api/v1/auth/refresh` is the
 * only reader of the refresh cookie, so that prefix is both sufficient and the
 * narrowest scope that works.
 */
const GMS_REFRESH_COOKIE_PATH = '/api/v1';

/**
 * The CSRF cookie stays at `/` on purpose, and this is the honest reason rather
 * than an oversight: it is a double-submit token that GMS's own frontend
 * JavaScript READS from the cookie jar while running on pages under `/gms`
 * (frontend/shared/lib/api-client.ts's readCookie) and echoes back as
 * `X-CSRF-Token` to `/api/v1`, where the backend compares the two. A single
 * cookie therefore has to be visible at BOTH `/gms` (to the page script) and
 * `/api/v1` (to the server), and the only path covering both on this origin is
 * `/`. Narrowing it to either one breaks every CSRF-protected GMS action.
 *
 * The exposure that leaves is small and of a different kind from the refresh
 * token's: it is non-httpOnly by design, carries no authority on its own, and is
 * worthless to a sibling system or an attacker without the access/refresh token
 * it accompanies. Closing it properly means giving GMS's API a path prefix, which
 * root CLAUDE.md explicitly protects as already-live routing.
 */
const GMS_CSRF_COOKIE_PATH = '/';

export function startGateway(): http.Server {
  const app = express();
  const { port, publicUrl, gmsFrontendTarget, gmsApiTarget } = IDP_CONFIG.gateway;

  // Apache fronts this app (`/gms/__sso`), so every request arrived from Apache's
  // loopback address and the rate limiters below were ONE shared counter for the
  // whole company. Trust exactly the configured number of proxy hops (same setting
  // and meaning as main.ts) so they key on the real client address.
  app.set('trust proxy', IDP_CONFIG.trustProxyHops);
  app.use(edgeClientIp); // the browser's real address from the edge header (see http/client-ip.ts)

  // This process previously had none of the hardening applied to the main IdP
  // app (no helmet, no rate limiting) despite proxying real user traffic —
  // CSP stays off for the same reason as main.ts: the GMS frontend/backend
  // render HTML/assets this process doesn't control and hasn't been
  // page-by-page audited for a strict CSP.
  app.use(helmet({
    contentSecurityPolicy: false,
    hsts: IDP_CONFIG.isProd ? undefined : false,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));

  // The one-time handoff code is a bearer secret (see bridge/session.ts) —
  // throttle redemption attempts against it specifically.
  const ssoHandoffLimiter = createLimiter('sso-handoff', { windowMs: 60_000, limit: 20 });
  // Light defense-in-depth ceiling for the rest of the proxied surface —
  // generous enough not to interfere with normal SPA/API/websocket traffic.
  const gatewayLimiter = createLimiter('gateway', { windowMs: 60_000, limit: 600 });
  app.use(gatewayLimiter);

  // One-time SSO handoff: seed the GMS SPA session on THIS origin, then continue.
  //
  // Accepted risk, documented rather than silently left implicit: the earlier
  // /bridge/gms/handoff hop (bridge/router.ts, same origin as the IdP) binds
  // the code to an httpOnly cookie and checks possession of it before
  // forwarding here — but this gateway runs on a DIFFERENT origin
  // (gms.localtest.me:4200), so that cookie never reaches this process at
  // all (cross-origin cookies aren't sent). By this final hop, `code` is a
  // bare one-time bearer secret with no further possession proof — mitigated
  // by a 2-minute TTL (bridge/session.ts) and single-use redemption
  // (takeGatewaySession deletes on read), but genuinely exploitable by
  // anyone who captures the code in transit (proxy log, referrer, browser
  // history) within that window, on an already-compromised network path.
  app.get('/__sso', ssoHandoffLimiter, async (req, res) => {
    const s = await takeGatewaySession(String(req.query.code ?? ''));
    if (!s) return res.status(400).send('SSO handoff expired — reopen GMS from the portal.');

    /**
     * Zustand persist envelope the GMS store expects (key gms-auth-session).
     *
     * P1-21: `accessToken` is deliberately NOT in here any more, and this must
     * stay in step with GMS's own `partialize` (frontend/state/auth.store.ts) —
     * GMS stopped persisting the token, so seeding one would put back exactly
     * the localStorage-resident bearer token that change removed, and by the
     * cross-system path rather than the local-login one.
     *
     * `authenticated: true` is the flag GMS's route guards now read. The real
     * credential travels as the httpOnly `gms_refresh_token` cookie set below,
     * which the SPA's bootstrapAccessToken() trades for an in-memory access
     * token on first load — the same path a reloaded local session takes, so
     * the bridged session is no longer a special case.
     */
    const persisted = {
      state: {
        authenticated: true,
        userId: s.userId,
        roles: s.roles,
        officeId: s.officeId,
        selectedRole: s.roles.length === 1 ? s.roles[0] : null,
        requiresPasswordChange: false,
      },
      version: 0,
    };
    /**
     * Same-origin refresh cookie so the SPA's /auth/refresh keeps the session alive.
     *
     * P1-11: scoped to `/api/v1`, matching GMS's own attachRefreshCookie
     * (appConfig.refreshCookiePath). It used to be `Path=/`, which on the shared
     * portal.examplecorp.com origin meant SSO handed GMS's refresh token to DMS,
     * MRS and SSO itself on every subsequent request. `/api/v1` is exclusively
     * GMS's API prefix and is the only place anything reads this cookie.
     *
     * The main IdP app's prefixCookiePath patch (main.ts) does not reach here —
     * the gateway is a separate Express app with no REWRITE_FLAG — so this has to
     * be set explicitly, and it has to stay in step with GMS's own value or the
     * bridged session's refresh silently stops working.
     */
    res.cookie('gms_refresh_token', s.gmsRefreshToken, { httpOnly: true, sameSite: 'lax', secure: IDP_CONFIG.isProd, path: GMS_REFRESH_COOKIE_PATH });
    // GMS's own double-submit CSRF cookie (shared/middleware/csrf.middleware.ts's
    // attachCsrfCookie) is normally set by GMS's own /auth/login or /auth/refresh
    // responses. A bridged session never calls either -- SSO mints the session
    // directly through GMS's internal /internal/sso/sessions API -- so without
    // this, gms_csrf_token stays unset until the access token naturally expires
    // (JWT_EXPIRES_IN=15m) and apiClient's first 401-triggered refresh finally
    // sets it. Any CSRF-protected action attempted before that (change password,
    // toggle 2FA, sign out -- all reachable from the very Profile page the SSO
    // handoff lands on) would 401 with "CSRF validation failed" for up to 15
    // minutes after every fresh SSO login. It's a pure double-submit check
    // (requireCsrf only compares this cookie's value against the X-CSRF-Token
    // header GMS's own apiClient already reads it into, per api-client.ts's
    // readCookie('gms_csrf_token')) -- no server-side secret involved -- so
    // minting one here, with the exact same attributes GMS's own
    // attachCsrfCookie uses, closes the gap with no GMS-side change needed.
    // Deliberately still Path=/ — see GMS_CSRF_COOKIE_PATH.
    res.cookie('gms_csrf_token', crypto.randomUUID(), { httpOnly: false, sameSite: 'strict', secure: IDP_CONFIG.isProd, path: GMS_CSRF_COOKIE_PATH });
    res.set('content-type', 'text/html; charset=utf-8');
    res.set('cache-control', 'no-store');
    /**
     * P2-8: this page is the gateway's ONLY HTML response, and it genuinely needs
     * an inline script — writing the minted session into the GMS SPA's own
     * localStorage on this origin is the entire purpose of the handoff. So it gets
     * a per-response nonce rather than 'unsafe-inline', and the policy is otherwise
     * strict. Everything else the gateway serves is a proxy pass-through, where
     * the CSP belongs on GMS's own responses (which is where P2-8 item 3 puts it).
     */
    const nonce = crypto.randomBytes(16).toString('base64');
    res.set(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        `script-src 'nonce-${nonce}'`,
        "style-src 'unsafe-inline'",
        "object-src 'none'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
      ].join('; '),
    );
    const landing = portalPathForRoles(s.roles);
    res.send(
      `<!doctype html><meta charset="utf-8"><title>Signing in to GMS…</title>` +
      `<body style="font-family:system-ui;padding:40px;color:#334155">Signing you in to GMS…` +
      `<script nonce="${nonce}">try{localStorage.setItem(${JSON.stringify(IDP_CONFIG.gms.sessionStorageKey)},` +
      `${JSON.stringify(JSON.stringify(persisted))});}catch(e){}location.replace(${JSON.stringify(landing)});</script></body>`,
    );
  });

  // GMS API — proxied same-origin to the GMS backend (prependPath keeps /api/v1).
  app.use('/api/v1', createProxyMiddleware({
    target: `${gmsApiTarget}/api/v1`,
    changeOrigin: true,
  }));

  // Realtime (socket.io) — proxied same-origin to the GMS backend so live
  // notifications/feeds work under the gateway origin.
  app.use('/socket.io', createProxyMiddleware({
    target: gmsApiTarget,
    changeOrigin: true,
    ws: true,
  }));

  // Everything else → the GMS frontend (Next.js dev server), incl. HMR websockets.
  app.use('/', createProxyMiddleware({
    target: gmsFrontendTarget,
    changeOrigin: true,
    ws: true,
  }));

  /**
   * Loopback-only, same as the main IdP app (IDP_CONFIG.host). Apache routes
   * exactly one path here in production — `/gms/__sso` → 127.0.0.1:4200, per
   * DEPLOYMENT-GUIDE.md:157 — so there has never been a reason for 4200 to be
   * reachable from the LAN. It was, because this listen() passed no host.
   */
  return app.listen(port, IDP_CONFIG.host, () => {
    logger.info({ publicUrl, host: IDP_CONFIG.host, gmsFrontendTarget, gmsApiTarget }, '[idp:gateway] listening');
  });
}
