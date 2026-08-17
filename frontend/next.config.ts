import type { NextConfig } from "next";
import path from "path";

const BACKEND = (
  process.env.SSO_BACKEND_URL ?? "http://localhost:7300"
).replace(/\/$/, "");

const nextConfig: NextConfig = {
  // The shared nginx reverse proxy serves this app below /sso in production. This is
  // injected during `next build`; leave it empty for the localhost dev server.
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || undefined,
  output: "standalone",
  compress: true,
  poweredByHeader: false,
  reactStrictMode: true,
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
  // `/portal/logout`, `/admin/users/:id/reset-password`) fall through here.
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
        { source: "/admin/:path*", destination: `${BACKEND}/admin/:path*` },
        { source: "/api/v1/:path*", destination: `${BACKEND}/api/v1/:path*` },
        { source: "/health", destination: `${BACKEND}/health` },
        { source: "/health/:path*", destination: `${BACKEND}/health/:path*` },
      ],
    };
  },
  webpack: (config) => {
    config.resolve.alias = {
      ...config.resolve.alias,
      "@features": path.resolve(__dirname, "./features"),
      "@shared": path.resolve(__dirname, "./shared"),
      "@state": path.resolve(__dirname, "./state"),
      "@providers": path.resolve(__dirname, "./providers"),
      "@app": path.resolve(__dirname, "./app"),
    };
    return config;
  },
};

export default nextConfig;
