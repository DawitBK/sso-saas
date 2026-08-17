'use server';

import { cookies } from 'next/headers';

/**
 * Server Actions for /portal/security — MUST be Server Actions, not a fetch()
 * to a separate Route Handler under /api/proxy/*, for the same reason as
 * app/(auth)/interaction/[uid]/actions.ts: the security CSRF cookie
 * (portal/router.ts's issueSecurityCsrf) is scoped to Path=/portal, so only a
 * request whose own path is under /portal ever receives it from the browser.
 * Server Actions are invoked by the browser POSTing back to the CURRENT
 * page's own URL (/portal/security), so the path always matches.
 */

const BACKEND = (process.env.SSO_BACKEND_URL ?? 'http://localhost:7300').replace(/\/$/, '');

export interface SecurityViewModel {
  view?: string;
  locals?: {
    userEmail: string;
    mfaEnabled: boolean;
    pending: { secret: string; uri: string } | null;
    canChangePassword: boolean;
    recentLogins: Array<{ success: boolean; reason: string | null; ip: string | null; created_at: string }>;
    mySessions: Array<{ kind: string; key: string; createdAt: string; expiresAt: string | null; current: boolean }>;
    error: string | null;
    passwordError: string | null;
    csrf: string;
  };
  redirect?: string;
  error?: string;
}

async function cookieHeader(): Promise<string> {
  const store = await cookies();
  return store.getAll().map((c) => `${c.name}=${c.value}`).join('; ');
}

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

async function parseViewModel(res: Response): Promise<SecurityViewModel> {
  await relaySetCookies(res);
  if (res.status >= 300 && res.status < 400) {
    return { redirect: res.headers.get('location') ?? '/portal/security' };
  }
  const body = (await res.json().catch(() => null)) as { view?: string; locals?: SecurityViewModel['locals'] } | null;
  if (!body?.view) return { error: 'Could not load security settings.' };
  return { view: body.view, locals: body.locals };
}

export async function getSecurityState(): Promise<SecurityViewModel> {
  const res = await fetch(`${BACKEND}/portal/security`, {
    headers: { cookie: await cookieHeader(), 'x-sso-ui': '1' },
    redirect: 'manual',
    cache: 'no-store',
  });
  return parseViewModel(res);
}

async function postSecurity(path: string, fields: Record<string, string>): Promise<SecurityViewModel> {
  const form = new URLSearchParams(fields);
  const res = await fetch(`${BACKEND}${path}`, {
    method: 'POST',
    headers: { cookie: await cookieHeader(), 'x-sso-ui': '1', 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
    redirect: 'manual',
    cache: 'no-store',
  });
  // Every POST here redirects back to /portal/security on both success and
  // failure (renderSecurity re-renders with an error, still a 200 from this
  // app's perspective since the backend's res.render was already intercepted
  // into JSON) — so a redirect just means "go re-fetch the state".
  if (res.status >= 300 && res.status < 400) {
    await relaySetCookies(res);
    return getSecurityState();
  }
  return parseViewModel(res);
}

export async function totpStart(csrf: string) {
  return postSecurity('/portal/security/totp/start', { csrf });
}
export async function totpConfirm(csrf: string, code: string) {
  return postSecurity('/portal/security/totp/confirm', { csrf, code });
}
export async function totpDisable(csrf: string, code: string) {
  return postSecurity('/portal/security/totp/disable', { csrf, code });
}
export async function changePassword(csrf: string, currentPassword: string, newPassword: string, confirmPassword: string) {
  return postSecurity('/portal/security/password/change', {
    csrf,
    current_password: currentPassword,
    new_password: newPassword,
    confirm_password: confirmPassword,
  });
}
export async function killSession(csrf: string, kind: string, key: string) {
  return postSecurity('/portal/security/sessions/kill', { csrf, kind, key });
}
