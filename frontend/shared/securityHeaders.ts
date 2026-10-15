/**
 * Security headers for every page this frontend serves, and the Content-Security-Policy that goes with a per-request nonce.
 *
 * WHY HERE. The backend's own CSP (backend/src/http/csp.ts) covers the handful of HTML pages the backend emits, and says so itself: the
 * policy that governs the sign-in form belongs on THIS process's responses, because this is the process that renders the form. Until
 * now there was none: the login page, the MFA step, the password forms and the whole admin console went out with no CSP and no
 * frame protection from here, relying on whatever the reverse proxy adds (the live Apache vhost adds HSTS, nosniff and a SAMEORIGIN
 * frame header but no CSP, and the mirror's vhost adds none of them).
 *
 * THE POLICY. Scripts run only if they carry this request's nonce (or were loaded by a script that does: 'strict-dynamic'), so an
 * injected <script> or an inline event handler cannot execute; nothing may frame the page (frame-ancestors, plus X-Frame-Options for
 * old browsers); forms and connections go to this origin only; <object>/<embed> and a changed <base> are refused. style-src keeps
 * 'unsafe-inline' on purpose: the console renders inline style="" attributes server-side, which a nonce cannot cover; injected CSS is
 * a far smaller exposure than injected script, and script is where the strictness is.
 *
 * SSO_CSP selects the mode at run time: `enforce` (default), `report-only` (log violations in the browser, block nothing; the way to
 * trial a change) or `off` (a break-glass that removes only the CSP header; the other headers stay).
 */
export type CspMode = 'enforce' | 'report-only' | 'off';

export function cspMode(value: string | undefined): CspMode {
  const v = (value ?? '').trim().toLowerCase();
  return v === 'report-only' || v === 'off' ? v : 'enforce';
}

export function buildCsp(nonce: string, dev: boolean): string {
  return [
    "default-src 'self'",
    // React needs eval in development for its debugging output; production uses none.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ''}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "manifest-src 'self'",
    "worker-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ');
}

/** The headers that do not depend on the request. HSTS is left to the reverse proxy that terminates TLS. */
export const STATIC_SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};

/** A fresh, unpredictable nonce per request (128 random bits, base64). */
export function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes));
}
