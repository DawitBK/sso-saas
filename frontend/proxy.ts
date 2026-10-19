import { NextRequest, NextResponse } from 'next/server';
import { buildCsp, cspMode, newNonce, STATIC_SECURITY_HEADERS } from './shared/securityHeaders';

/**
 * Canonical-host guard — the frontend-side half of the backend's own guard
 * in SSO/backend/src/main.ts (see its comment for the full "why": localhost
 * and 127.0.0.1 are permanently separate cookie-storage origins by browser
 * design, and a stray hit on the wrong host mid-flow is what actually
 * produces oidc-provider's "authorization request has expired" — not a real
 * expiry, a cookie that was set on a different origin than the one asking
 * for it back). This half covers hitting THIS frontend port directly (9301
 * in mirror, 7301 in production), bypassing Apache entirely — every request
 * that reaches the backend through Apache already passed through here
 * first, so catching it at this layer stops the mismatch before a single
 * cookie is ever set on the wrong origin.
 *
 * `proxy.ts` (not `middleware.ts` — Next 16 renamed the file convention;
 * `middleware.ts` still works but logs a deprecation warning on every build).
 *
 * NEXT_PUBLIC_APP_ORIGIN (see .env.mirror / .env.production) is the
 * browser-facing origin this deployment is actually served at — mirroring
 * the existing NEXT_PUBLIC_BASE_PATH pattern (shared/apiPath.ts) and, on the
 * backend, the canonical host IDP_CONFIG.issuer already derives from
 * IDP_ISSUER. The localhost:7301 fallback matches this app's other
 * env-driven defaults (SSO_BACKEND_URL in next.config.ts) for root-hosted
 * local dev, which has no .env file at all.
 *
 * `x-forwarded-host` is read in preference to `host` because it's the only
 * header guaranteed to carry the ORIGINAL browser Host through Apache in
 * every environment this runs in — checked against both real configs, not
 * assumed: the mirror vhost (apache/conf/extra/httpd-mirror.conf) does not
 * set `ProxyPreserveHost`, so Apache's default (Off) sends this process
 * `Host: 127.0.0.1:9301` (the proxy target) and relies on mod_proxy's
 * automatic `X-Forwarded-Host` for the real one; the real production vhost
 * (apache/conf/extra/httpd-ssl.conf) sets `ProxyPreserveHost On` instead, so
 * `Host` itself already carries `portal.examplecorp.com` and `X-Forwarded-Host`
 * agrees with it. Preferring `x-forwarded-host` is correct either way.
 */
const APP_ORIGIN = process.env.NEXT_PUBLIC_APP_ORIGIN ?? 'http://localhost:7301';
const BASE_PATH = (process.env.NEXT_PUBLIC_BASE_PATH ?? '').replace(/\/+$/, '');

// Legitimate server-to-server / monitoring GETs made directly against this
// port (uptime checks, discovery fetched by a client library) — never a
// browser navigation, and must not be redirected.
const SKIP_PATH_PREFIXES = ['/health', '/jwks', '/.well-known'];

function isSkippedPath(pathname: string): boolean {
  const bare = BASE_PATH && pathname.startsWith(BASE_PATH) ? pathname.slice(BASE_PATH.length) || '/' : pathname;
  return SKIP_PATH_PREFIXES.some((p) => bare === p || bare.startsWith(`${p}/`));
}

/**
 * Continue to the page with this request's nonce and Content-Security-Policy on both sides: the request (so Next puts the nonce on the
 * scripts it emits and the layout can read it from `x-nonce`) and the response (so the browser enforces it). See shared/securityHeaders.ts.
 */
function secured(request: NextRequest): NextResponse {
  const mode = cspMode(process.env.SSO_CSP);
  const nonce = newNonce();
  const csp = buildCsp(nonce, process.env.NODE_ENV === 'development');
  const header = mode === 'report-only' ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  if (mode !== 'off') requestHeaders.set(header, csp);
  const response = NextResponse.next({ request: { headers: requestHeaders } });
  if (mode !== 'off') response.headers.set(header, csp);
  for (const [name, value] of Object.entries(STATIC_SECURITY_HEADERS)) response.headers.set(name, value);
  return response;
}

/**
 * Pages the SSO BACKEND renders itself (oidc-provider's end-session page). Where Apache routes straight to the backend they never reach this
 * process; where everything goes through this frontend (the hosted SaaS edition behind Vercel) this process would replace the backend's
 * Content-Security-Policy with its own, whose nonce the backend's inline script does not carry: the browser blocked the script and sign-out
 * ended on a blank page. These paths keep the backend's own headers.
 */
const BACKEND_RENDERED_PREFIXES = ['/session/'];

function isBackendRendered(pathname: string): boolean {
  const bare = BASE_PATH && pathname.startsWith(BASE_PATH) ? pathname.slice(BASE_PATH.length) || '/' : pathname;
  return BACKEND_RENDERED_PREFIXES.some((p) => bare.startsWith(p));
}

export function proxy(request: NextRequest) {
  if (isBackendRendered(request.nextUrl.pathname)) return NextResponse.next();

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return secured(request);
  }

  let canonical: URL;
  try {
    canonical = new URL(APP_ORIGIN);
  } catch {
    return secured(request);
  }

  const forwardedHost = request.headers.get('x-forwarded-host');
  const host = (forwardedHost ? forwardedHost.split(',')[0]?.trim() : undefined) || request.headers.get('host') || '';
  if (!host || host === canonical.host) {
    return secured(request);
  }

  if (isSkippedPath(request.nextUrl.pathname)) {
    return secured(request);
  }

  const target = request.nextUrl.clone();
  target.protocol = canonical.protocol;
  target.host = canonical.host;
  target.port = canonical.port;
  return NextResponse.redirect(target, 302);
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
