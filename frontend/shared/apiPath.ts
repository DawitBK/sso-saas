/**
 * Prefixes a root-relative app path with this deployment's basePath.
 *
 * WHY THIS EXISTS: Next's `basePath` rewrites pages, `next/link`, the router and
 * rewrite SOURCES — but NOT raw `fetch()` calls. This app was written to sit at
 * a domain root and calls `fetch('/api/v1/...')` and `fetch('/portal/logout')`
 * directly in ~22 places. Served at https://portal.examplecorp.com/sso those
 * resolve at the DOMAIN root, where the shared nginx reverse proxy proxies `/api/` to
 * GMS on 7200 — which answers "Cannot GET /api/v1/portal". Silent, and it looks
 * like an SSO bug rather than a path bug.
 *
 * NEXT_PUBLIC_BASE_PATH is read at build time and inlined into the browser
 * bundle (that's why it must carry the NEXT_PUBLIC_ prefix). It is the SAME
 * value next.config.ts feeds to `basePath`, so the two cannot disagree. Empty
 * in dev, where localhost:7301 already is the root.
 *
 * Use for every root-relative fetch target. Do not use for `next/link` hrefs or
 * `router.push()` — Next already prefixes those, and doing it twice yields
 * /sso/sso/...
 */
const BASE_PATH = (process.env.NEXT_PUBLIC_BASE_PATH ?? '').replace(/\/+$/, '');

export function apiPath(path: string): string {
  if (!BASE_PATH) return path;
  // Absolute URLs and already-prefixed paths pass through untouched.
  if (!path.startsWith('/') || path.startsWith('//')) return path;
  if (path === BASE_PATH || path.startsWith(`${BASE_PATH}/`)) return path;
  return `${BASE_PATH}${path}`;
}

export { BASE_PATH };
