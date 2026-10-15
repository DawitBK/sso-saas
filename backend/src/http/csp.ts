/**
 * Content-Security-Policy for the SSO backend (P2-8).
 *
 * The finding as originally written assumed this process renders the platform's
 * login form, MFA prompt and password-change form. It does not, and hasn't since
 * the UI split: `http/view-model.ts` wraps `res.render` so every call site
 * returns `{ view, locals }` JSON, and the Next.js frontend on 7301 is the only
 * process that turns that into a page. The EJS templates this replaced were
 * deleted on 2026-09-06. So a nonce threaded through EJS would protect
 * nothing here — the CSP that governs the login form belongs on the frontend's
 * responses, which is a separate change in a separate process.
 *
 * What this process DOES emit as HTML, exhaustively:
 *
 *   1. `GET /session/end` — oidc-provider's RP-initiated-logout confirmation,
 *      via `logoutSource` in oidc/provider.ts. The confirmation branch has no
 *      script at all (P1-5 removed the blanket auto-submit); the auto-submit
 *      branch has one inline `onload` handler, which needs the nonce.
 *   2. oidc-provider's own error pages (`renderError`) — static HTML, no script.
 *   3. `GET /bridge/gms/handoff`'s error page — goes through res.render, so it is
 *      JSON, not HTML.
 *
 * Everything else the backend returns is JSON or a redirect, for which a strict
 * policy costs nothing. The old blanket `contentSecurityPolicy: false` was
 * justified by "oidc-provider renders some of its own HTML ... hasn't been
 * page-by-page audited" — that audit is the list above.
 *
 * `'unsafe-inline'` is deliberately absent from script-src. A nonce and
 * 'unsafe-inline' cannot coexist usefully: a browser that understands the nonce
 * ignores 'unsafe-inline' entirely, so including it only weakens the policy for
 * older browsers while doing nothing for current ones.
 */

import crypto from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

/** Per-request nonce, for the handful of inline scripts enumerated above. */
export function cspMiddleware(_req: Request, res: Response, next: NextFunction): void {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      `script-src 'self' 'nonce-${nonce}'`,
      // Inline styles only. The pages listed above use a `style=""` attribute for
      // basic layout and no external stylesheet; script injection is the exposure
      // that matters here, and style-src does not gate it.
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self'",
      // No XHR/WebSocket target other than this origin. The backend's own pages
      // make no requests at all; this bounds anything injected into them.
      "connect-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      // Belt and braces with helmet's frameguard: frame-ancestors is the modern
      // control and X-Frame-Options the legacy one, and clickjacking the consent
      // or logout page is exactly what both are for.
      "frame-ancestors 'none'",
      "form-action 'self'",
    ].join('; '),
  );
  next();
}
