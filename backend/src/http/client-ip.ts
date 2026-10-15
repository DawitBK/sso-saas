/**
 * The client address to RECORD for a request (sign-in events, the admin audit
 * trail).
 *
 * Express already resolves `req.ip` from X-Forwarded-For according to `trust
 * proxy` (TRUST_PROXY_HOPS, default 1: trust Apache, take the last address it
 * appended). This only tidies the form so the same client is always the same
 * string: Node reports an IPv4 client on a dual-stack socket as `::ffff:1.2.3.4`,
 * and a proxy can forward `1.2.3.4:51234` or `[::1]:51234` with a port. The
 * lockout gate counts failures per address, so "1.2.3.4" and "::ffff:1.2.3.4"
 * must not count as two different sources.
 *
 * Returns '' when there is no usable address (never a made-up value).
 */
export function normalizeClientIp(raw: string | undefined | null): string {
  let ip = String(raw ?? '').trim();
  if (!ip) return '';
  // [::1]:51234 -> ::1
  const bracketed = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) ip = bracketed[1];
  // 1.2.3.4:51234 -> 1.2.3.4 (an IPv6 literal has several colons, so only strip a lone ":port")
  else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(ip)) ip = ip.slice(0, ip.lastIndexOf(':'));
  // ::ffff:1.2.3.4 -> 1.2.3.4
  if (/^::ffff:\d{1,3}(\.\d{1,3}){3}$/i.test(ip)) ip = ip.slice(7);
  return ip.length > 64 ? ip.slice(0, 64) : ip;
}

/** The recorded client address for an Express request. */
export function clientIpOf(req: { ip?: string | undefined }): string {
  return normalizeClientIp(req.ip);
}

/**
 * The header the edge Apache sets from the TCP address of the browser's connection
 * (`RequestHeader set X-Edge-Client-IP "expr=%{REMOTE_ADDR}"`). `set` overwrites whatever the browser sent, so unlike
 * X-Forwarded-For it cannot be forged by a client behind Apache.
 *
 * Why it exists: SSO sits behind TWO proxies (Apache -> the Next.js frontend, whose rewrites forward to this backend), and
 * the Next hop appends its own address to X-Forwarded-For. With TRUST_PROXY_HOPS=1 `req.ip` is then always the Next hop,
 * 127.0.0.1, for every visitor; raising it to 2 would make a client-supplied X-Forwarded-For entry count as the address on
 * the routes Apache sends straight to the backend. A header only Apache writes has neither problem.
 */
export const EDGE_CLIENT_IP_HEADER = 'x-kg-client-ip';

const LOOPBACK = /^(127\.\d+\.\d+\.\d+|::1|::ffff:127\.\d+\.\d+\.\d+)$/;
const IP_SHAPE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+)$/i;

/** Express middleware: when the request reached us from the local proxy chain and carries the edge header, make `req.ip` that address. */
export function edgeClientIp(req: { socket?: { remoteAddress?: string }; headers: Record<string, unknown> }, _res: unknown, next: () => void): void {
  const peer = req.socket?.remoteAddress ?? '';
  const raw = req.headers[EDGE_CLIENT_IP_HEADER];
  const value = normalizeClientIp(Array.isArray(raw) ? raw[0] : (raw as string | undefined));
  if (LOOPBACK.test(peer) && value && IP_SHAPE.test(value)) {
    Object.defineProperty(req, 'ip', { value, configurable: true, enumerable: true });
  }
  next();
}
