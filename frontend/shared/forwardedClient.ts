import { headers } from 'next/headers';

/**
 * The browser's real address and user-agent, for server-to-server calls from
 * this Next process to the SSO backend.
 *
 * Why this exists: Server Actions (sign-in, MFA, password change, security
 * settings) call the backend from the Next process, not from the browser, so the
 * backend saw the Next process's own loopback address and Node's default
 * user-agent ("node") on every one of them. Every sign-in row therefore read
 * 127.0.0.1 / "node", and because the per-IP lockout and rate-limit gates key on
 * that address, they all collapsed onto a single shared bucket too.
 *
 * What is forwarded: the incoming X-Forwarded-For verbatim. Apache appends the
 * connecting client as the LAST entry, and the backend's `trust proxy` setting
 * (TRUST_PROXY_HOPS, default 1) trusts exactly one hop and takes the last entry,
 * so a client-supplied prefix cannot spoof it. This is only safe because the Next
 * server listens on loopback behind Apache; do not expose it directly.
 * When there is no forwarded header (a developer hitting the port directly) nothing
 * is forwarded and the backend honestly reports loopback.
 */
export async function forwardedClientHeaders(): Promise<Record<string, string>> {
  const h = await headers();
  const out: Record<string, string> = {};
  const forwardedFor = h.get('x-forwarded-for');
  if (forwardedFor) out['x-forwarded-for'] = forwardedFor;
  const userAgent = h.get('user-agent');
  if (userAgent) out['user-agent'] = userAgent;
  return out;
}
