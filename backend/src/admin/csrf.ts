/**
 * Double-submit CSRF for the admin console, same scheme as interactions/csrf.ts
 * but scoped to the /admin cookie path.
 */

import type { Request, Response } from 'express';
import crypto from 'node:crypto';
import { IDP_CONFIG } from '../config.js';

const COOKIE = 'idp_admin_csrf';

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

export function issueCsrf(res: Response, isProd: boolean): string {
  const token = crypto.randomBytes(24).toString('hex');
  // Prefixed with publicBasePath — see the matching note in interactions/csrf.ts.
  // Under /sso the admin console is served at /sso/admin/..., which doesn't
  // start with a bare '/admin', so the browser would never send this cookie back.
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: isProd, path: `${IDP_CONFIG.publicBasePath}/admin` });
  return token;
}

export function validateCsrf(req: Request): boolean {
  const cookie = parseCookies(req.headers.cookie)[COOKIE];
  const submitted = (req.body?.csrf as string) ?? '';
  if (!cookie || !submitted || cookie.length !== submitted.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(submitted));
}
