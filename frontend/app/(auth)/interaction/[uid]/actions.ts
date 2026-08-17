'use server';

import { cookies } from 'next/headers';

/**
 * Server Actions for the OIDC interaction flow (login / MFA / forced
 * password-change). MUST be Server Actions, not a fetch() to a separate
 * Route Handler under /api/proxy/* — oidc-provider scopes its interaction
 * session cookie (`_interaction`) to `Path=/interaction/{uid}`, and the CSRF
 * cookie interactions/csrf.ts issues is scoped the same way. A browser only
 * attaches a cookie to requests whose path is prefixed by the cookie's own
 * Path, so a fetch to any other path (e.g. /api/proxy/...) silently never
 * carries it — confirmed by curl during this fix, an earlier proxy-route
 * version of this file shipped with exactly that bug. Server Actions are
 * invoked by the browser POSTing back to the CURRENT page's own URL
 * (/interaction/{uid}), so the path always matches.
 */

const BACKEND = (process.env.SSO_BACKEND_URL ?? 'http://localhost:7300').replace(/\/$/, '');

export interface ViewModelResult {
  view?: string;
  locals?: Record<string, unknown>;
  redirect?: string;
  error?: string;
}

async function cookieHeader(): Promise<string> {
  const store = await cookies();
  return store.getAll().map((c) => `${c.name}=${c.value}`).join('; ');
}

/** Parse one Set-Cookie header value and apply it to the outgoing response
 *  via the Next.js cookie store (only writable inside a Server Action). */
async function relayOneSetCookie(raw: string): Promise<void> {
  const parts = raw.split(';').map((p) => p.trim());
  const [nameValue, ...attrParts] = parts;
  const eq = nameValue.indexOf('=');
  if (eq === -1) return;
  const name = nameValue.slice(0, eq);
  const value = decodeURIComponent(nameValue.slice(eq + 1));

  const attrs: Record<string, string> = {};
  for (const attr of attrParts) {
    const i = attr.indexOf('=');
    if (i === -1) attrs[attr.toLowerCase()] = 'true';
    else attrs[attr.slice(0, i).toLowerCase()] = attr.slice(i + 1);
  }

  const store = await cookies();
  store.set(name, value, {
    path: attrs.path ?? '/',
    httpOnly: 'httponly' in attrs,
    secure: 'secure' in attrs,
    sameSite: (attrs.samesite?.toLowerCase() as 'lax' | 'strict' | 'none' | undefined) ?? 'lax',
    maxAge: attrs['max-age'] ? Number(attrs['max-age']) : undefined,
  });
}

async function relaySetCookies(res: Response): Promise<void> {
  const getSetCookie = (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  const raws = typeof getSetCookie === 'function' ? getSetCookie.call(res.headers) : [];
  for (const raw of raws) await relayOneSetCookie(raw);
}

/** GET the current interaction's view-model (login/totp/change-password + csrf). */
export async function getInteractionState(uid: string): Promise<ViewModelResult> {
  const res = await fetch(`${BACKEND}/interaction/${encodeURIComponent(uid)}`, {
    headers: { cookie: await cookieHeader(), 'x-sso-ui': '1' },
    redirect: 'manual',
    cache: 'no-store',
  });
  await relaySetCookies(res);

  if (res.status >= 300 && res.status < 400) {
    return { redirect: res.headers.get('location') ?? '/' };
  }
  const body = (await res.json().catch(() => null)) as { view?: string; locals?: Record<string, unknown> } | null;
  if (!body?.view) return { error: 'This sign-in link is invalid or has expired.' };
  return { view: body.view, locals: body.locals };
}

/** POST a login/totp/password/confirm/abort submission for this interaction. */
export async function submitInteractionStep(
  uid: string,
  step: 'login' | 'totp' | 'password' | 'confirm' | 'abort',
  fields: Record<string, string>,
): Promise<ViewModelResult> {
  const form = new URLSearchParams(fields);
  const res = await fetch(`${BACKEND}/interaction/${encodeURIComponent(uid)}/${step}`, {
    method: 'POST',
    headers: {
      cookie: await cookieHeader(),
      'x-sso-ui': '1',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: form.toString(),
    redirect: 'manual',
    cache: 'no-store',
  });
  await relaySetCookies(res);

  if (res.status >= 300 && res.status < 400) {
    return { redirect: res.headers.get('location') ?? '/' };
  }
  const body = (await res.json().catch(() => null)) as { view?: string; locals?: Record<string, unknown> } | null;
  if (!body?.view) return { error: 'Something went wrong. Please try again.' };
  return { view: body.view, locals: body.locals };
}
