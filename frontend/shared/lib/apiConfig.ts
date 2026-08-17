// Relative/same-origin — MUST NOT be an absolute cross-origin URL. The
// backend's session/CSRF cookies are SameSite=Lax; a cross-origin browser
// fetch (even with withCredentials/CORS configured) silently drops those
// cookies since a Lax cookie only rides along on a top-level navigation, not
// an XHR/fetch from a different origin. next.config.ts's rewrites() proxy
// `/api/v1/*` to the real backend so this stays same-origin from :7301.
export const API_BASE_URL = '';

export const API_ENDPOINTS = {
  // Auth — login/MFA/forced-password-change go through Server Actions in
  // app/(auth)/interaction/[uid]/actions.ts, and logout is a direct fetch to
  // /portal/logout (same-origin, rewritten to the backend) — both reach the
  // real, unduplicated backend flows rather than a separate
  // /api/v1/auth/login|logout that never existed on the backend. Neither can
  // go through a generic /api/proxy/* route: the cookies involved are scoped
  // to Path=/interaction/{uid} and Path=/portal respectively, so anything
  // outside those exact path prefixes never receives them from the browser.
  SESSION: '/api/v1/auth/session',

  // Portal
  PORTAL: '/api/v1/portal',

  // Admin
  ADMIN_STATS: '/api/v1/admin/stats',
  ADMIN_USERS: '/api/v1/admin/users',
  ADMIN_GROUPS: '/api/v1/admin/groups',
  ADMIN_CLIENTS: '/api/v1/admin/clients',
  ADMIN_SESSIONS: '/api/v1/admin/sessions',
  ADMIN_LOGINS: '/api/v1/admin/logins',
  ADMIN_AUDIT: '/api/v1/admin/audit',
};
