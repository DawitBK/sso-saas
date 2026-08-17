/**
 * Double-submit CSRF for the login/consent forms. On render we set a random
 * value in a SameSite=Lax cookie AND embed it in a hidden field; on POST the two
 * must match. A cross-site forged POST can neither read nor set the cookie.
 */

import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { IDP_CONFIG } from '../config.js';

const COOKIE = 'idp_csrf';

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

/** Issue a CSRF token, set the cookie, return the value for the template. */
export function issueCsrf(res: Response, isProd: boolean): string {
  const token = crypto.randomBytes(24).toString('hex');
  res.cookie(COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,
    // Prefixed with publicBasePath (empty in dev): the browser only attaches a
    // cookie when the request path matches Path as a PREFIX. Under
    // https://portal.examplecorp.com/sso the login page is served at
    // /sso/interaction/{uid}, which does not start with a bare '/interaction' —
    // so the cookie was silently never sent back on submit, and every login
    // failed with "Session expired, please try again."
    path: `${IDP_CONFIG.publicBasePath}/interaction`,
  });
  return token;
}

/** Validate the submitted token against the cookie. */
export function validateCsrf(req: Request): boolean {
  const cookie = parseCookies(req.headers.cookie)[COOKIE];
  const submitted = (req.body?.csrf as string) ?? '';
  if (!cookie || !submitted || cookie.length !== submitted.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(submitted));
}
