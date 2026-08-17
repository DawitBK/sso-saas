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

export function apiV1Router(provider: Provider): Router {
  const router = Router();

  // Platform endpoints (health, metrics)
  router.use('/', platformApiRouter());

  // Authentication endpoints
  router.use('/auth', authApiRouter());

  // Portal endpoints
  router.use('/portal', portalApiRouter());

  // Admin console endpoints (GET operations)
  router.use('/admin', adminApiRouter());

  // Admin console mutations (POST/PUT/DELETE operations)
  router.use('/admin', adminMutationsRouter(provider));

  return router;
}

export { sendOk, sendError } from './platform.router.js';
