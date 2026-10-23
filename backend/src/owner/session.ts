/**
 * Which portal session a request belongs to, and the hash a challenge or ticket is bound to.
 *
 * The raw `idp_portal` cookie value is a bearer credential and is never stored or logged: only a purpose-prefixed SHA-256 of it is (the same idea as
 * the console, which shows sessions by `sha256(key)`). A ticket minted in one browser session is therefore useless in another, even for the same owner.
 */
import crypto from 'node:crypto';
import type { Request } from 'express';
import { getPortalSession, type PortalSession } from '../portal/session.js';

function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i === -1 || part.slice(0, i).trim() !== name) continue;
    try {
      out.push(decodeURIComponent(part.slice(i + 1).trim()));
    } catch {
      /* a malformed value is not a session */
    }
  }
  return out;
}

export function sessionHashOf(key: string): string {
  return crypto.createHash('sha256').update(`owner-session\n${key}`).digest('hex');
}

/** The live portal session for the request and the hash of its cookie, or null. A stale same-name cookie never shadows the live one. */
export async function resolveSession(req: Request): Promise<{ session: PortalSession; sessionHash: string } | null> {
  for (const v of cookieValues(req, 'idp_portal')) {
    const session = await getPortalSession(v);
    if (session) return { session, sessionHash: sessionHashOf(v) };
  }
  return null;
}
