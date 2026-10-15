import type { NextConfig } from "next";
import path from "path";
import { fileURLToPath } from "url";

// Turbopack picks a project root by walking up for the nearest lockfile, and
// there is a stray package.json/package-lock.json in this machine's home
// directory (C:\Users\admin). Without an explicit root it infers one outside
// the repository, warns, and — because this is an `output: "standalone"`
// build — traces the wrong tree into the server bundle. Pin it to this app.
const PROJECT_ROOT = path.dirname(fileURLToPath(import.meta.url));

const BACKEND = (
  process.env.SSO_BACKEND_URL ?? "http://localhost:7300"
).replace(/\/$/, "");
const DIST_DIR = process.env.NEXT_DIST_DIR || ".next";

const nextConfig: NextConfig = {
  // The shared Apache vhost serves this app below /sso in production. This is
  // injected during `next build`; leave it empty for the localhost dev server.
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || undefined,
  output: "standalone",
  distDir: DIST_DIR,
  compress: true,
  poweredByHeader: false,
  reactStrictMode: true,
  devIndicators: false,
  experimental: {
    optimizePackageImports: ["lucide-react"],
  },
  async headers() {
    return [
      {
        source: "/sw.js",
        headers: [
          { key: "Service-Worker-Allowed", value: "/" },
          { key: "Cache-Control", value: "no-cache, no-store, must-revalidate" },
        ],
      },
    ];
  },
  // Same-origin reverse proxy to the SSO backend — mirrors what the current
  // EJS frontend's server.ts does with http-proxy-middleware. This is load-
  // bearing, not cosmetic: session/CSRF cookies set by the backend are
  // SameSite=Lax, so a browser fetch from a DIFFERENT origin (cross-port)
  // would silently drop them even with credentials:'include'/CORS configured
  // correctly. Routing everything through this app's own origin (7301) is
  // what makes the whole auth flow (and every /api/v1 call) actually work.
  //
  // Returned under `fallback` (NOT a plain array): a plain-array/`afterFiles`
  // rewrite is checked after static pages/public files but BEFORE dynamic
  // routes — so `/admin/:path*` was silently swallowing our own dynamic pages
  // (`/admin/users/[id]`, i.e. any real user's detail page) before Next ever
  // got to match them, serving the backend's raw view-model JSON instead of
  // rendering the page. `fallback` is checked after BOTH static and dynamic
  // routes, so our pages always win and only genuinely unmatched paths (e.g.
  // `/portal/logout`) fall through here. There is no `/admin/*` rewrite: the first, server-rendered console on the backend
  // was retired 2026-10-11, so an unmatched `/admin/...` is a plain 404.
  async rewrites() {
    return {
      beforeFiles: [],
      afterFiles: [],
      fallback: [
        // oidc-provider's authorization endpoint is renamed to /authorize here
        // (see oidc/provider.ts's `routes: { authorization: '/authorize' }`,
        // done to match DMS's existing client config) — NOT the oidc-provider
        // default of /auth. Must be a wildcard: after an interaction finishes,
        // oidc-provider redirects the browser to resume the grant at
        // /authorize/{uid} (its standard post-interaction resume URL), not just
        // bare /authorize — an exact-match rewrite 404s that hop.
        { source: "/authorize", destination: `${BACKEND}/authorize` },
        {
          source: "/authorize/:path*",
          destination: `${BACKEND}/authorize/:path*`,
        },
        { source: "/token", destination: `${BACKEND}/token` },
        { source: "/me", destination: `${BACKEND}/me` },
        { source: "/jwks", destination: `${BACKEND}/jwks` },
        { source: "/session/:path*", destination: `${BACKEND}/session/:path*` },
        {
          source: "/.well-known/:path*",
          destination: `${BACKEND}/.well-known/:path*`,
        },
        { source: "/bridge/:path*", destination: `${BACKEND}/bridge/:path*` },
        { source: "/portal/:path*", destination: `${BACKEND}/portal/:path*` },
        { source: "/api/v1/:path*", destination: `${BACKEND}/api/v1/:path*` },
        { source: "/health", destination: `${BACKEND}/health` },
        { source: "/health/:path*", destination: `${BACKEND}/health/:path*` },
      ],
    };
  },
  // Next 16 builds with Turbopack by default. The webpack `resolve.alias`
  // block that used to live here only restated the four @shared/@state/
  // @providers/@app aliases that tsconfig.json's `paths` already declares, and
  // Turbopack reads those natively — so it was redundant even on 15. Leaving
  // it in place is not harmless under 16: a config with a `webpack` key and no
  // `turbopack` key is a hard build error ("This build is using Turbopack,
  // with a `webpack` config and no `turbopack` config").
  turbopack: {
    root: PROJECT_ROOT,
  },
};

export default nextConfig;
