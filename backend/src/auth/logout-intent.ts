/**
 * "This sign-out came from us" marker for RP-initiated logout (P1-5).
 *
 * oidc-provider's end-session endpoint renders a confirmation form on purpose:
 * without it, `GET /session/end?client_id=…` is a state-changing GET that any
 * third-party page can trigger with a hidden iframe, ending a signed-in user's
 * entire SSO session across the portal, DMS and GMS with no interaction. The
 * provider config used to auto-submit that form on load for every caller, which
 * removed the protection wholesale.
 *
 * The marker restores it without reintroducing a second click for our own users.
 * `POST /portal/logout` (already CSRF-protected, already a POST) sets this cookie
 * immediately before redirecting to `/session/end`; the end-session page
 * auto-submits only when it is present, and otherwise renders a real
 * confirmation button.
 *
 * Presence alone is sufficient proof, and no server-side record is needed: the
 * cookie is httpOnly and scoped to this origin, so a cross-site attacker can
 * neither read it nor set it. What they *can* do — replay a URL — is exactly what
 * now hits the confirmation form.
 *
 * The value is random rather than a constant only so that it cannot be guessed
 * and pinned by something with partial write access to the cookie jar (e.g. a
 * sibling subdomain setting a domain cookie); the length check is what the
 * end-session side actually verifies.
 */

import crypto from 'node:crypto';
import type { Response } from 'express';
import { IDP_CONFIG } from '../config.js';

export const LOGOUT_INTENT_COOKIE = 'idp_logout_intent';

/**
 * 60 seconds. Long enough for the redirect (and for the portal frontend's
 * fetch-then-navigate double hop through /session/end), short enough that a
 * stale marker cannot sit in the jar waiting to be exploited by a later
 * cross-site request.
 */
const LOGOUT_INTENT_TTL_MS = 60_000;

const TOKEN_BYTES = 24;
const TOKEN_HEX_LENGTH = TOKEN_BYTES * 2;

/**
 * Scoped to /session, so the cookie is only ever sent to the end-session
 * endpoint and nothing else. Prefixed with publicBasePath — see the matching
 * note in admin/csrf.ts.
 */
function cookiePath(): string {
  return `${IDP_CONFIG.publicBasePath}/session`;
}

/** Called by POST /portal/logout, just before redirecting to /session/end. */
export function setLogoutIntent(res: Response): void {
  res.cookie(LOGOUT_INTENT_COOKIE, crypto.randomBytes(TOKEN_BYTES).toString('hex'), {
    httpOnly: true,
    // 'lax' and not 'strict': the browser reaches /session/end by a top-level
    // navigation that 'strict' would still allow (same-site), but the portal
    // frontend is served from the Next.js app on the same origin via a rewrite,
    // and 'lax' is the setting used consistently by every other cookie here.
    sameSite: 'lax',
    secure: IDP_CONFIG.isProd,
    path: cookiePath(),
    maxAge: LOGOUT_INTENT_TTL_MS,
  });
}

/**
 * Read side, used from oidc-provider's Koa context. Only shape is checked — see
 * the header note on why presence is the security property.
 */
export function hasLogoutIntent(cookieValue: string | undefined): boolean {
  return typeof cookieValue === 'string' && /^[0-9a-f]+$/.test(cookieValue) && cookieValue.length === TOKEN_HEX_LENGTH;
}
