/**
 * What a relying party's redirect and post-logout addresses may be. An address is where an authorization code (or a signed-out
 * browser) is sent, so a loose rule here is an open redirect or a stolen sign-in: every address must be an exact, complete URL.
 *
 *   - https only, except http on a loopback host (localhost, 127.0.0.1) where that is expected: never in production, allowed on
 *     the production-parity mirror (a single machine, loopback by design) and in development.
 *   - no wildcard (a `*` would match addresses nobody reviewed), no fragment, no credentials in the address.
 *   - at most MAX_URIS, duplicates removed, surrounding spaces ignored.
 * oidc-provider compares redirect_uri by exact string match; nothing here loosens that.
 */
export const MAX_URIS = 20;

export interface UriRules {
  /** Production (or anything not on a local origin): loopback addresses are refused. */
  isProd: boolean;
  /** NODE_ENV: the mirror runs on one machine, so loopback is correct there even though isProd is true. */
  env: string;
  /** A redirect list must not be empty (a client with no redirect address cannot sign anyone in); a logout list may be. */
  allowEmpty: boolean;
}

export type UriResult = { ok: true; value: string[] } | { ok: false; error: string };

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export function validateClientUris(raw: unknown, rules: UriRules, label = 'Address'): UriResult {
  if (!Array.isArray(raw) || raw.some((u) => typeof u !== 'string')) return { ok: false, error: `${label} list must be a list of addresses.` };
  const cleaned = [...new Set((raw as string[]).map((u) => u.trim()).filter((u) => u.length > 0))];
  if (cleaned.length === 0 && !rules.allowEmpty) return { ok: false, error: `${label} list cannot be empty: the application could not sign anyone in.` };
  if (cleaned.length > MAX_URIS) return { ok: false, error: `At most ${MAX_URIS} addresses.` };
  const loopbackAllowed = !rules.isProd || rules.env === 'mirror';
  for (const uri of cleaned) {
    if (uri.length > 2000) return { ok: false, error: `An address is too long: ${uri.slice(0, 60)}…` };
    if (uri.includes('*')) return { ok: false, error: `Wildcards are not allowed: ${uri}` };
    let url: URL;
    try {
      url = new URL(uri);
    } catch {
      return { ok: false, error: `Not a complete address (include https://): ${uri}` };
    }
    if (url.hash) return { ok: false, error: `An address cannot contain a # fragment: ${uri}` };
    if (url.username || url.password) return { ok: false, error: `An address cannot contain a user name or password: ${uri}` };
    const loopback = LOOPBACK.has(url.hostname.toLowerCase());
    if (loopback && !loopbackAllowed) return { ok: false, error: `A local address (${uri}) cannot be used in production: it would only work on the server itself.` };
    if (url.protocol === 'https:') continue;
    if (url.protocol === 'http:' && loopback) continue;
    return { ok: false, error: `Use https:// (plain http is only accepted for local development addresses): ${uri}` };
  }
  return { ok: true, value: cleaned };
}
