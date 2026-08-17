/**
 * Example Corp Identity Provider — production entry point.
 *
 * Central OIDC provider + SSO portal + gateway relay for DMS, GMS, and future
 * apps. Built on oidc-provider (Panva) with a Postgres store. See config.ts /
 * README for the architecture.
 *
 * Endpoints:
 *   /.well-known/openid-configuration   discovery (served by oidc-provider)
 *   /jwks                               JWKS
 *   /auth /token /me /session/end       OIDC (oidc-provider)
 *   /interaction/:uid                   our login + consent screens
 *   /portal                             SSO app launcher
 *   /admin                              user/group/role admin console (admin-group gated)
 *   /bridge/gms/*                       GMS token bridge (no GMS changes)
 *   /internal/gms/users/:email/roles    inbound: GMS manages its per-user SSO role grants
 *   /health                             liveness
 *
 * (An earlier `/gms/api/*` relay attempt here was dead code — 401ing on every
 * request, gated on a cookie nothing ever set. The gateway's own GMS API relay
 * lives entirely in gateway/server.ts on its own port; this one was removed.)
 */

import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';
import http from 'node:http';
import { IDP_CONFIG } from './config.js';
import { runMigrations } from './db/migrate.js';
import { pool } from './db/pool.js';
import { buildProvider } from './oidc/provider.js';
import { interactionRouter } from './interactions/router.js';
import { gmsBridgeRouter } from './bridge/router.js';
import { startGateway } from './gateway/server.js';
import { portalRouter } from './portal/router.js';
import { adminRouter } from './admin/router.js';
import { gmsRoleGrantsRouter } from './admin/gms-role-grants.routes.js';
import { apiV1Router } from './api/v1/index.js';
import { openApiSpec } from './api/v1/openapi.js';
import swaggerUi from 'swagger-ui-express';
import { viewModelMiddleware } from './http/view-model.js';
import { logger } from './logging/logger.js';
import { resyncActiveAdSessions } from './auth/ad-resync.worker.js';

/** Sweep tables with no other purge path: oidc-provider's own artifacts (full
 *  claims payloads incl. ad_groups) and the sign-in event log — both have an
 *  expiry/age but nothing was ever deleting past it. */
function startPurgeJob(): void {
  const LOGIN_EVENT_RETENTION_DAYS = 90;
  const run = async (): Promise<void> => {
    try {
      await pool.query(`DELETE FROM oidc_artifacts WHERE expires_at IS NOT NULL AND expires_at < NOW()`);
      await pool.query(`DELETE FROM idp_login_events WHERE created_at < NOW() - INTERVAL '${LOGIN_EVENT_RETENTION_DAYS} days'`);
    } catch (err) {
      logger.error({ err }, '[idp:purge] sweep failed');
    }
  };
  run();
  setInterval(run, 60 * 60_000).unref();
}

/** Platform audit finding 4.7: AD group membership was only ever rechecked
 *  at login, leaving a mid-session AD group removal in effect until the
 *  session naturally expired (14 days) or the user logged in again. Runs
 *  every 30 minutes, scoped to only AD users with a live session right now
 *  — a no-op entirely when LDAP isn't configured (resyncActiveAdSessions
 *  checks isAdEnabled() itself). See ad-resync.worker.ts. */
function startAdResyncJob(): void {
  const run = (): void => {
    resyncActiveAdSessions().catch((err) => {
      logger.error({ err }, '[idp:ad-resync] sweep failed');
    });
  };
  run();
  setInterval(run, 30 * 60_000).unref();
}

async function main(): Promise<void> {
  // Apply schema before anything touches the DB (dev convenience; in prod run
  // `npm run db:migrate` as a deploy step).
  if (!IDP_CONFIG.isProd) {
    await runMigrations();
  }

  const provider = await buildProvider();

  const app = express();
  app.set('trust proxy', IDP_CONFIG.trustProxyHops);

  // Platform-wide request tracing and baseline browser/API hardening. OIDC's
  // own response handling remains untouched; these headers are additive.
  // Only accept an inbound correlation id that actually looks like one (the
  // typical UUID/request-id charset) — this value is later relayed verbatim
  // as a header on SSO's internal call to GMS (bridge/gms.ts's gmsRequest()),
  // so an unsanitized client-supplied value would let a crafted header inject
  // arbitrary content into GMS's logs (log forging). A length check alone
  // isn't enough; anything outside the safe charset is discarded in favor of
  // a freshly generated id rather than rejecting the request outright.
  const CORRELATION_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
  app.use((req, res, next) => {
    const incoming = req.header('x-correlation-id') || req.header('x-request-id');
    const requestId = incoming && CORRELATION_ID_PATTERN.test(incoming) ? incoming : crypto.randomUUID();
    res.locals.requestId = requestId;
    res.setHeader('x-request-id', requestId);
    res.setHeader('x-correlation-id', requestId);
    next();
  });

  // Serve-under-a-subpath fix. This service's routers emit ROOT-relative
  // locations (29 `res.redirect('/portal...')` / `'/interaction/...'` call
  // sites) because SSO was originally written to sit at a domain root. When
  // it's served at https://portal.examplecorp.com/sso those send the browser to
  // /portal — which nginx has no rule for, so it 404s from the docroot.
  //
  // Patches the raw http.ServerResponse PROTOTYPE, not just this app's res
  // instances, because oidc-provider is Koa-based internally: provider.
  // callback() adapts a Koa context onto this same raw response object, and
  // Koa's ctx.redirect()/ctx.set('Location', ...) call
  // res.setHeader('Location', ...) DIRECTLY — never Express's res.redirect
  // method. A res.redirect-only patch (what this used to be) missed
  // oidc-provider's own internal redirects entirely, e.g. the "resume the
  // authorization request" hop issued by provider.interactionFinished()
  // after a successful login, which came back as a bare /authorize/{uid}
  // with no /sso prefix — a 404 from the reverse proxy.
  //
  // A per-request INSTANCE override (`res.setHeader = ...`, what this used
  // to be) is not enough either — confirmed in prod (2026-08) via the
  // [idp:redirect-fix] diagnostic logs never firing for oidc-provider's own
  // `_interaction`/`_interaction_resume` cookies at all. Root cause: those
  // cookies are written through the `cookies` npm package (used internally
  // by Koa/oidc-provider's ctx.cookies), and that package's `set()`
  // deliberately does `res.set ? http.OutgoingMessage.prototype.setHeader :
  // res.setHeader` before writing Set-Cookie — i.e. on an Express response
  // (which always has `res.set`) it grabs the RAW PROTOTYPE method to
  // bypass exactly this kind of instance-level monkeypatch. That left the
  // resume cookie's Path stuck at the unprefixed `/authorize/{uid}` (see the
  // mountPath note below) while the matching Location header — set via a
  // plain res.setHeader call, which the cookies package does NOT route
  // through — correctly became `/sso/authorize/{uid}`. The browser then
  // never sends the Path-mismatched cookie back on the follow-up request,
  // and oidc-provider's resume.js throws exactly "authorization request has
  // expired" when it finds the cookie missing. Patching the prototype
  // method itself closes this: the cookies package still calls the same
  // (now-patched) function via `.call(res, ...)`, it just can't skip past it
  // anymore.
  //
  // Scoped via a per-request marker (set below) rather than applying to
  // every response in the process, because this same process also runs the
  // gateway's own Express app (gateway/server.ts, port 4200) proxying GMS —
  // whose Location/Set-Cookie headers must NOT get a /sso prefix.
  if (IDP_CONFIG.publicBasePath) {
    const base = IDP_CONFIG.publicBasePath;
    // oidc-provider's post-login "resume authorization" redirect is NOT
    // root-relative — it's an ABSOLUTE url built from just the issuer's
    // ORIGIN plus routes.authorization (oidc-provider's urlFor() derives its
    // mountPath from req.originalUrl/req.baseUrl, both empty here since
    // nginx strips /sso before the request ever reaches this process), e.g.
    // "https://portal.examplecorp.com/authorize/{uid}", silently dropping the
    // issuer's own /sso path entirely. Handle both shapes: a root-relative
    // path, or an absolute URL on our OWN origin whose pathname is missing
    // the prefix.
    const ownOrigin = new URL(IDP_CONFIG.issuer).origin;

    /**
     * Top-level path segments THIS service owns. Everything else on the same
     * origin belongs to a SIBLING system behind the shared nginx reverse proxy
     * (/gms, /dms, /mrs, /Identity, /strapi, ...).
     *
     * This allowlist is load-bearing, not defensive tidiness. Every relying
     * party's redirect_uri is an absolute URL on this very origin —
     * https://portal.examplecorp.com/dms/auth/callback,
     * .../mrs/api/auth/sso/callback, .../gms/login — and so is the GMS
     * bridge's own handoff hop (bridge/router.ts's
     * `${gateway.publicUrl}/__sso`, i.e. .../gms/__sso). An
     * origin-only check rewrote all of those to /sso/dms/..., /sso/mrs/...,
     * /sso/gms/... — paths nginx has no rule for — so login *into* SSO
     * succeeded and then every downstream app 404'd on the final hop back.
     * Only prefix paths that are actually ours.
     */
    const OWN_PATH_SEGMENTS = new Set([
      'authorize', 'token', 'me', 'jwks', 'session', '.well-known',
      'interaction', 'portal', 'admin', 'bridge', 'api', 'health',
      'introspection', 'revocation', 'device',
    ]);
    // Strip any query/fragment before reading the first segment: root-relative
    // Location values arrive as a raw target, not a parsed pathname, so a
    // single-segment redirect like "/portal?x=1" would otherwise be read as the
    // segment "portal?x=1" and fail to match.
    const ownsPath = (pathname: string): boolean =>
      OWN_PATH_SEGMENTS.has((pathname.split(/[?#]/)[0] ?? '').split('/')[1] ?? '');

    const prefixPath = (p: string): string =>
      p === base || p.startsWith(`${base}/`) ? p : `${base}${p}`;

    /** Location-header rewrite — prefixes ONLY this service's own paths. */
    const prefixed = (url: string): string => {
      if (url.startsWith('/') && !url.startsWith('//')) {
        return ownsPath(url) ? prefixPath(url) : url;
      }
      try {
        const u = new URL(url);
        if (u.origin !== ownOrigin) return url;
        if (u.pathname === base || u.pathname.startsWith(`${base}/`)) return url;
        if (!ownsPath(u.pathname)) return url;
        u.pathname = `${base}${u.pathname}`;
        return u.toString();
      } catch {
        // Not a parseable absolute URL — leave it alone.
      }
      return url;
    };

    // A cookie's Path attribute rewrite. Deliberately NOT allowlisted the way
    // Location is: every cookie this backend sets is its own and is only ever
    // read back by this backend, so all root-relative paths get the prefix —
    // including a bare "/" (the idp_portal session cookie), which must become
    // "/sso/" so it is still sent on /sso/portal and /sso/admin.
    const prefixCookiePath = (cookieStr: string): string =>
      cookieStr.replace(/(;\s*Path=)([^;]+)/i, (_m, p1: string, p2: string) => {
        const p = p2.trim();
        if (!p.startsWith('/') || p.startsWith('//')) return `${p1}${p}`;
        return `${p1}${prefixPath(p)}`;
      });

    const REWRITE_FLAG = Symbol('sso-prefix-rewrite');
    app.use((_req, res, next) => {
      (res as unknown as Record<symbol, boolean>)[REWRITE_FLAG] = true;
      next();
    });

    const originalSetHeader = http.OutgoingMessage.prototype.setHeader;
    http.OutgoingMessage.prototype.setHeader = function patchedSetHeader(
      this: InstanceType<typeof http.ServerResponse>,
      name: string,
      value: number | string | readonly string[],
    ) {
      if (!(this as unknown as Record<symbol, boolean>)[REWRITE_FLAG]) {
        return originalSetHeader.call(this, name, value);
      }
      const reqPath = (this as unknown as { req?: { originalUrl?: string } }).req?.originalUrl;
      if (typeof name === 'string' && name.toLowerCase() === 'location' && typeof value === 'string') {
        const out = prefixed(value);
        // debug, not info: a Location header on a login/logout redirect carries a
        // raw authorization code, state, and (on some hops) an id_token JWT whose
        // claims include email/name/role — same "must not sit in the production
        // log by default" reasoning as the Set-Cookie case just below.
        logger.debug({ path: reqPath, via: 'setHeader', original: value, rewritten: out }, '[idp:redirect-fix] Location seen');
        return originalSetHeader.call(this, name, out);
      }
      if (typeof name === 'string' && name.toLowerCase() === 'set-cookie') {
        const rewrite = (v: string) => prefixCookiePath(v);
        const out = Array.isArray(value) ? value.map(rewrite) : rewrite(value as string);
        // debug, not info: these lines carry raw cookie VALUES (CSRF tokens,
        // session keys). Useful while diagnosing the subpath cookie-Path bug,
        // but they must not sit in the production log by default — raise
        // LOG_LEVEL to debug to turn them back on.
        logger.debug({ path: reqPath, via: 'setHeader', original: value, rewritten: out }, '[idp:redirect-fix] Set-Cookie seen');
        return originalSetHeader.call(this, name, out as string | readonly string[]);
      }
      return originalSetHeader.call(this, name, value);
    } as typeof http.OutgoingMessage.prototype.setHeader;

    // Belt-and-suspenders: the setHeader patch alone did NOT fix the
    // oidc-provider post-login "resume" redirect in practice (still landed
    // on a bare /authorize/{uid}), so this also covers the case where
    // Location is baked directly into a writeHead(status, headersObject)
    // call instead of a separate setHeader call. writeHead has three
    // overloads — (status), (status, headers), (status, reason, headers).
    const originalWriteHead = http.ServerResponse.prototype.writeHead;
    http.ServerResponse.prototype.writeHead = function patchedWriteHead(
      this: InstanceType<typeof http.ServerResponse>,
      ...args: unknown[]
    ) {
      if (!(this as unknown as Record<symbol, boolean>)[REWRITE_FLAG]) {
        return (originalWriteHead as (...a: unknown[]) => typeof this).apply(this, args);
      }
      const reqPath = (this as unknown as { req?: { originalUrl?: string } }).req?.originalUrl;
      const headersArg = typeof args[1] === 'object' ? args[1] : args[2];
      if (headersArg && typeof headersArg === 'object') {
        for (const key of Object.keys(headersArg as Record<string, unknown>)) {
          if (key.toLowerCase() !== 'location') continue;
          const val = (headersArg as Record<string, unknown>)[key];
          if (typeof val === 'string') {
            const out = prefixed(val);
            // debug, not info — same reasoning as the setHeader Location case
            // above: this carries raw authorization codes/state/id_token JWTs.
            logger.debug({ path: reqPath, via: 'writeHead', original: val, rewritten: out }, '[idp:redirect-fix] Location seen');
            (headersArg as Record<string, unknown>)[key] = out;
          }
        }
      }
      return (originalWriteHead as (...a: unknown[]) => typeof this).apply(this, args);
    } as typeof http.ServerResponse.prototype.writeHead;
  }

  // Security headers (Directive §6.9). CSP left off for now: oidc-provider
  // renders some of its own HTML (error/consent edge cases) directly and
  // hasn't been page-by-page audited for inline-script/style dependencies —
  // enabling a strict CSP blind could break those pages. The explicit
  // per-request headers below (nosniff, frame-deny, referrer-policy) are the
  // same baseline this file already set manually; helmet now also adds
  // COOP/CORP/X-DNS-Prefetch-Control/etc. on top for free.
  app.use(helmet({
    contentSecurityPolicy: false,
    hsts: IDP_CONFIG.isProd ? undefined : false,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  }));

  // Rate limiting (Directive §7.5) — SSO previously had none at all, unlike
  // DMS/GMS. In-memory store (SSO has no Redis dependency today; revisit if
  // SSO ever runs more than one process). Scoped to the actual credential-
  // entry surfaces: the login/MFA/password-change form submissions and the
  // OIDC token endpoint, not a blanket global limiter that could throttle
  // legitimate SSO-wide traffic without first tuning a safe ceiling.
  const authLimiter = rateLimit({ windowMs: 60_000, limit: 20, standardHeaders: true, legacyHeaders: false });
  const tokenLimiter = rateLimit({ windowMs: 60_000, limit: 60, standardHeaders: true, legacyHeaders: false });

  // When the 7301 frontend asks for a view model (X-SSO-UI: 1), res.render
  // returns JSON instead of HTML so EJS can run in the frontend process.
  app.use(viewModelMiddleware);

  // Versioned application API. OIDC discovery, authorization, token and JWKS
  // endpoints intentionally remain at their protocol-defined paths.
  app.use('/api/v1', express.json({ limit: '1mb' }), apiV1Router(provider));

  // OpenAPI docs for SSO's own custom API surface (Directive §6.11, §7.2) -
  // matches GMS's own /api-docs + /api-docs.json pattern. Enabled by default
  // outside production; requires an explicit opt-in env var in production,
  // same posture as GMS's ENABLE_API_DOCS.
  const apiDocsEnabled = !IDP_CONFIG.isProd || process.env.ENABLE_API_DOCS === 'true';
  if (apiDocsEnabled) {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(openApiSpec, {
      customSiteTitle: 'SSO Platform API Docs',
    }));
    app.get('/api-docs.json', (_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(openApiSpec);
    });
  }

  // ── Health / operability ──────────────────────────────────────────────────
  app.get('/health', (_req, res) => {
    res.json({ status: 'ok', issuer: IDP_CONFIG.issuer, gmsBridge: IDP_CONFIG.gms.enabled });
  });

  // Readiness: liveness + a real DB round-trip (the IdP is useless without it).
  app.get('/health/ready', async (_req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ status: 'ready', db: 'ok' });
    } catch (err) {
      res.status(503).json({ status: 'not_ready', db: 'unreachable', error: (err as Error).message });
    }
  });

  // Operational counters (JSON; totals only — no user data).
  app.get('/metrics', async (_req, res) => {
    try {
      const { rows } = await pool.query<Record<string, string>>(
        `SELECT
           (SELECT COUNT(*) FROM idp_users) AS users_total,
           (SELECT COUNT(*) FROM idp_users WHERE is_active) AS users_active,
           (SELECT COUNT(*) FROM idp_users WHERE totp_enabled) AS users_mfa_enrolled,
           (SELECT COUNT(*) FROM oidc_artifacts WHERE kind = 'Session' AND payload->>'accountId' IS NOT NULL AND (expires_at IS NULL OR expires_at > NOW())) AS sessions_sso_active,
           (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'portal' AND expires_at > NOW()) AS sessions_portal_active,
           (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'gateway' AND expires_at > NOW()) AS sessions_gateway_active,
           (SELECT COUNT(*) FROM idp_login_events WHERE created_at > NOW() - INTERVAL '1 hour') AS logins_attempted_1h,
           (SELECT COUNT(*) FROM idp_login_events WHERE success = FALSE AND created_at > NOW() - INTERVAL '1 hour') AS logins_failed_1h,
           (SELECT COUNT(*) FROM idp_signing_keys WHERE is_active) AS signing_keys_active`,
      );
      res.set('cache-control', 'no-store');
      res.json(Object.fromEntries(Object.entries(rows[0]).map(([k, v]) => [k, Number(v)])));
    } catch (err) {
      res.status(503).json({ error: (err as Error).message });
    }
  });

  // Root → the SSO portal (friendly landing instead of oidc-provider's 404).
  app.get('/', (_req, res) => res.redirect('/portal'));

  // ── Our routes (scoped body parsers so oidc-provider gets raw bodies) ──────
  app.use('/portal', portalRouter());
  app.use('/admin', adminRouter(provider));
  app.use('/interaction', authLimiter, express.urlencoded({ extended: false }), interactionRouter(provider));
  app.use('/bridge', gmsBridgeRouter());
  app.use('/token', tokenLimiter);
  // Inbound: GMS calling into SSO to manage per-user role grants (directive §6.3).
  // Versioned mount is the standard path (matches GMS's own /api/v1/internal/sso
  // convention, per directive §5); the unversioned mount is kept live alongside it
  // as the backward-compatible prior version during the migration window, not as
  // an oversight — remove once no caller depends on it (PLATFORM-GAP-010).
  app.use('/api/v1/internal/gms', express.json({ limit: '256kb' }), gmsRoleGrantsRouter());
  app.use('/internal/gms', express.json({ limit: '256kb' }), gmsRoleGrantsRouter());

  // Teach oidc-provider's OWN internal ctx.oidc.urlFor() about the /sso
  // mount point. oidc_context.js derives urlFor's mountPath by (in order):
  //   1. req.originalUrl vs. the koa-internal request.url (always empty here
  //      -- nginx strips /sso before the request ever reaches this process,
  //      so originalUrl never contains it)
  //   2. ctx.mountPath (koa-mount convention -- not applicable, this is Express)
  //   3. req.baseUrl (Express convention for `app.use('/prefix', subApp)`)
  // We can't literally do `app.use('/sso', provider.callback())` -- nginx
  // already stripped /sso, so Express would never match that prefix against
  // the incoming (already-unprefixed) path and every oidc-provider route
  // would 404. Setting req.baseUrl directly hits fallback #3 without
  // requiring Express to have actually consumed a /sso path segment.
  //
  // WHY THIS MATTERS BEYOND THE ALREADY-FIXED interaction-resume REDIRECT:
  // urlFor() backs EVERY endpoint URL oidc-provider emits, including ones
  // that live in a response BODY rather than a Location/Set-Cookie header --
  // which the prefixed()/prefixCookiePath() patch below can never reach, no
  // matter how it's extended, since it only rewrites headers. Confirmed live
  // (2026-08-02) both were wrong before this fix:
  //   - GET /.well-known/openid-configuration: every endpoint except `issuer`
  //     (authorization_endpoint, token_endpoint, jwks_uri, end_session_endpoint,
  //     revocation_endpoint, introspection_endpoint, userinfo_endpoint) pointed
  //     at the bare domain root instead of /sso/... -- spec-non-compliant, and
  //     would break any future OIDC client that does real discovery instead of
  //     hardcoding endpoint URLs (DMS/GMS/MRS all hardcode theirs today, which
  //     is the only reason this hasn't broken a real login).
  //   - RP-initiated logout's confirmation page (oidc/provider.ts's
  //     logoutSource): the auto-submitted <form action="..."> is built from
  //     `ctx.oidc.urlFor('end_session_confirm')` and baked straight into the
  //     HTML body. It posted to bare /session/end/confirm, which nginx has
  //     no rule for -- every sign-out 404'd on the reverse proxy's own docroot (not even
  //     Next.js's styled 404) right after the portal's "Sign out" button.
  // This single middleware fixes both, and any other urlFor()-based body
  // content we haven't hit yet, instead of patching each one individually.
  if (IDP_CONFIG.publicBasePath) {
    app.use((req, _res, next) => {
      (req as unknown as { baseUrl: string }).baseUrl = IDP_CONFIG.publicBasePath;
      next();
    });
  }

  // ── Everything else → oidc-provider (auth, token, jwks, userinfo, discovery)
  app.use(provider.callback());

  const server = app.listen(IDP_CONFIG.port, () => {
    logger.info(
      { issuer: IDP_CONFIG.issuer, gmsBridge: IDP_CONFIG.gms.enabled, port: IDP_CONFIG.port },
      'Example Corp Identity Provider listening',
    );
  });

  // Same-origin gateway for the GMS SPA (separate port, shared process/memory).
  if (IDP_CONFIG.gms.enabled) startGateway();

  startPurgeJob();
  startAdResyncJob();

  // Let in-flight /token and /interaction requests finish instead of a hard
  // kill on every rolling deploy.
  const shutdown = (signal: string): void => {
    logger.info({ signal }, '[idp] shutting down');
    server.close(() => pool.end().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('unhandledRejection', (err) => {
    logger.error({ err }, '[idp] unhandled rejection');
  });
}

main().catch((err) => {
  logger.error({ err }, '[idp] fatal startup error');
  process.exit(1);
});
