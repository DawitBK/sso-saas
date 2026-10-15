const STATIC_CACHE = "sso-static-v3";
const OFFLINE_URL = "offline.html";

// Mirrors next.config.ts's own rewrites().fallback sources exactly — every
// path that hits the oidc-provider backend (auth, tokens, session, portal,
// admin, api/v1, health) must always go to the network, never the cache.
// The login/interaction page's Server Actions (POST) are already covered by
// the method guard below, independent of this regex.
const BYPASS_RE =
  /^\/(authorize(\/.*)?|token|me|jwks|session(\/.*)?|\.well-known(\/.*)?|bridge(\/.*)?|portal(\/.*)?|admin(\/.*)?|api\/v1(\/.*)?|health(\/.*)?)$/;

// Stale-while-revalidate, not cache-first: serve the cached copy immediately
// (if any) but always kick off a network fetch to refresh the cache for next
// time. `_next/static/*` is content-hashed in a production build, so in prod
// this behaves identically to cache-first (a new build's fresh hash means a
// fresh cache entry — the background revalidation only ever refetches
// something byte-identical to what's cached). In `next dev`, that same path
// is served at stable, unhashed filenames whose content changes on every
// save; a pure cache-first strategy would then serve that first-cached
// version forever, which is what previously forced disabling the SW outright
// in dev. Stale-while-revalidate instead self-heals within one reload in
// either environment — no environment check needed here or in registration.
async function staleWhileRevalidate(request) {
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(request);
  const network = fetch(request)
    .then((response) => {
      if (response.ok) cache.put(request, response.clone());
      return response;
    })
    .catch(() => cached);
  return cached || network;
}

self.addEventListener("install", (event) => {
  // Take over immediately instead of waiting for every open tab to close —
  // makes a fixed/updated sw.js (e.g. after the version bump below) apply on
  // the very next reload rather than requiring a full browser restart.
  self.skipWaiting();
  event.waitUntil(
    caches.open(STATIC_CACHE).then((cache) => cache.add(OFFLINE_URL)),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      // Purge every cache from a previous STATIC_CACHE name — bump the
      // version above whenever a bad/stale entry needs to be force-evicted
      // from everyone's Cache Storage, not just this browser's.
      caches.keys().then((keys) =>
        Promise.all(keys.filter((key) => key !== STATIC_CACHE).map((key) => caches.delete(key))),
      ),
      self.clients.claim(),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return; // Server Actions, form posts, logout — always network

  const url = new URL(request.url);
  const scope = new URL(self.registration.scope).pathname; // '/' or '/sso/'
  const appPath = url.pathname.startsWith(scope) ? "/" + url.pathname.slice(scope.length) : url.pathname;

  if (BYPASS_RE.test(appPath)) return; // OIDC/portal/admin/api — always network
  if (appPath.includes("/_next/image")) return; // dynamic, never content-hashed
  if (appPath.startsWith("/_next/static/")) {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }
  if (request.mode === "navigate") {
    event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL)));
    return;
  }
  // everything else: pass through, no caching either direction
});
