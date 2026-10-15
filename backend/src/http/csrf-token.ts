/**
 * The double-submit CSRF token every SSO form and console mutation uses: an httpOnly cookie plus the same value in the request body.
 *
 * The token is REUSED while the browser already holds one, rather than replaced on every page render. Replacing it made every
 * second view invalidate the first: two tabs open on the Security page, or a page that fetches its state twice (React StrictMode
 * does in development), left the form holding a token whose cookie had already been overwritten, and the next click was refused
 * as a forged request with nothing on screen to say why. A token that lives as long as its cookie is the normal double-submit
 * design and loses no protection: it is httpOnly, only ever sent to this origin, and unguessable.
 */
import crypto from 'node:crypto';
import type { CookieOptions, Response } from 'express';

const TOKEN = /^[a-f0-9]{48}$/;

function cookieValues(header: string | undefined, name: string): string[] {
  if (!header) return [];
  const out: string[] = [];
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) out.push(decodeURIComponent(part.slice(i + 1).trim()));
  }
  return out;
}

/** The token to put in the page: the one the browser already sent for `name` if it is well formed, else a fresh one. The cookie is (re)written either way so its attributes stay current. */
export function reuseOrIssueCsrf(res: Response, name: string, options: CookieOptions): string {
  const sent = cookieValues(res.req?.headers?.cookie, name).find((v) => TOKEN.test(v));
  const token = sent ?? crypto.randomBytes(24).toString('hex');
  res.cookie(name, token, options);
  return token;
}
