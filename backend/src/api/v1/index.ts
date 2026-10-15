/**
 * API v1 Router - aggregates all v1 API endpoints
 */

import { Router } from 'express';
import type Provider from 'oidc-provider';
import { platformApiRouter } from './platform.router.js';
import { authApiRouter } from './auth.router.js';
import { portalApiRouter } from './portal.router.js';
import { adminApiRouter } from './admin.router.js';
import { adminMutationsRouter } from './admin-mutations.router.js';
import { csrfRouter, publicRouter, settingsAdminRouter } from './settings.router.js';
import { systemRouter } from './system.router.js';
import { clientsRouter } from './clients.router.js';
import { usersBulkRouter } from './users-bulk.router.js';
import { activityRouter } from './activity.router.js';
import { publicResetRequestRouter, resetRequestsAdminRouter } from './reset-requests.router.js';
import { createLimiter } from '../../infrastructure/rateLimiter.js';

export function apiV1Router(provider: Provider): Router {
  const router = Router();

  // Platform endpoints (health, metrics)
  router.use('/', platformApiRouter());

  // "Forgot your password?" (no email: the request goes to the administrators). Five (RESET_REQUEST_RATE_LIMIT) a quarter hour per address, and the answer never depends on the account.
  // RESET_REQUEST_RATE_LIMIT (default 5) raises it for the browser test suite, which asks several times a run.
  const resetRequestLimit = Math.max(1, Number.parseInt(process.env.RESET_REQUEST_RATE_LIMIT ?? '', 10) || 5);
  router.use('/auth/password-reset-request', createLimiter('reset-request', { windowMs: 15 * 60_000, limit: resetRequestLimit }), publicResetRequestRouter());

  // Authentication endpoints
  router.use('/auth', authApiRouter());

  // Portal endpoints
  router.use('/portal', portalApiRouter());

  // Unauthenticated, read-only: the branding the sign-in page needs before anyone is signed in
  router.use('/public', publicRouter());

  // A CSRF token for pages that mutate without a GET of their own that issues one
  router.use('/admin/csrf', csrfRouter());

  // Platform settings (own router: its routes are not under the user/group/session families below)
  router.use('/admin/settings', settingsAdminRouter());

  // CSV exports of the audit trail and the sign-in log (ahead of admin.router: /audit/export and /logins/export are not ids)
  router.use('/admin', activityRouter());

  // The open password reset requests (before admin.router so the path is not read as something else)
  router.use('/admin/password-reset-requests', resetRequestsAdminRouter());

  // Users: CSV export and bulk actions (ahead of admin.router so /export and /bulk are not read as a user id)
  router.use('/admin/users', usersBulkRouter());

  // Relying-party management (its GET / supersedes the old read-only list; GET /:clientId/users still falls through to admin.router)
  router.use('/admin/clients', clientsRouter());

  // How this process and the systems around it are doing (the console's System page)
  router.use('/admin/system', systemRouter());

  // Admin console endpoints (GET operations)
  router.use('/admin', adminApiRouter());

  // Admin console mutations (POST/PUT/DELETE operations)
  router.use('/admin', adminMutationsRouter(provider));

  return router;
}

export { sendOk, sendError } from './platform.router.js';
