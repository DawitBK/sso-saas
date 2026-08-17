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

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { IDP_CONFIG } from '../config.js';
import { takeGatewaySession } from '../bridge/session.js';
import { logger } from '../logging/logger.js';

/**
 * Map GMS roles to their SPA landing route (mirrors GMS's getPortalPathForRole).
 *
 * In dev, the gateway proxies GMS's frontend root directly (no base path), so
 * these paths resolve as-is under the gateway's own dev origin. In production
 * the gateway is only reachable at the narrow `/gms/__sso` nginx rule — the
 * rest of `/gms` is served directly by GMS's own already-proven nginx rule,
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

export function startGateway(): void {
  const app = express();
  const { port, publicUrl, gmsFrontendTarget, gmsApiTarget } = IDP_CONFIG.gateway;

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
  const ssoHandoffLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false });
  // Light defense-in-depth ceiling for the rest of the proxied surface —
  // generous enough not to interfere with normal SPA/API/websocket traffic.
  const gatewayLimiter = rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: true, legacyHeaders: false });
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

    // Zustand persist envelope the GMS store expects (key gms-auth-session).
    const persisted = {
      state: {
        accessToken: s.gmsAccessToken,
        userId: s.userId,
        roles: s.roles,
        officeId: s.officeId,
        selectedRole: s.roles.length === 1 ? s.roles[0] : null,
        requiresPasswordChange: false,
      },
      version: 0,
    };
    // Same-origin refresh cookie so the SPA's /auth/refresh keeps the session alive.
    res.cookie('gms_refresh_token', s.gmsRefreshToken, { httpOnly: true, sameSite: 'lax', secure: IDP_CONFIG.isProd, path: '/' });
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
    res.cookie('gms_csrf_token', crypto.randomUUID(), { httpOnly: false, sameSite: 'strict', secure: IDP_CONFIG.isProd, path: '/' });
    res.set('content-type', 'text/html; charset=utf-8');
    res.set('cache-control', 'no-store');
    const landing = portalPathForRoles(s.roles);
    res.send(
      `<!doctype html><meta charset="utf-8"><title>Signing in to GMS…</title>` +
      `<body style="font-family:system-ui;padding:40px;color:#334155">Signing you in to GMS…` +
      `<script>try{localStorage.setItem(${JSON.stringify(IDP_CONFIG.gms.sessionStorageKey)},` +
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

  app.listen(port, () => {
    logger.info({ publicUrl, gmsFrontendTarget, gmsApiTarget }, '[idp:gateway] listening');
  });
}
