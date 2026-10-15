/**
 * GMS token bridge.
 *
 * The IdP authenticates the staff member, resolves their GMS role (per-user
 * grant, then AD group mapping, then `guest` — see auth/client-role-claims.ts),
 * then calls GMS's deliberately small internal SSO API with that role. GMS
 * still mints and owns its own session/token and signing keys; the IdP never
 * connects to the GMS database or mints a GMS token directly. But as of the
 * directive §6.3 role migration, SSO — not GMS's local `roles` table — is the
 * system-of-record for which role that session gets, for any account with an
 * SSO-resolved opinion (see GMS's `issueSsoSession` for the precedence that
 * consumes `initialRoles` below).
 */

import crypto from 'node:crypto';
import { IDP_CONFIG } from '../config.js';
import { pool as idpPool } from '../db/pool.js';
import { resolveGmsRoles } from '../auth/client-role-claims.js';
import { createInternalApiClient } from '../infrastructure/internalApiClient.js';

export interface BridgeIdentity {
  email: string;
  givenName: string;
  familyName: string;
  groups: string[];
}

export interface GmsSession {
  accessToken: string;
  refreshToken: string;
  userId: number;
  roles: string[];
  officeId: number | null;
}

function assertConfigured(): void {
  if (!IDP_CONFIG.gms.enabled) throw new Error('GMS bridge is disabled (GMS_BRIDGE_ENABLED=false)');
  if (!IDP_CONFIG.gms.internalApiKey) throw new Error('GMS_INTERNAL_API_KEY is not configured');
  if (!IDP_CONFIG.gms.apiBase) throw new Error('GMS_API_BASE is not configured');
}

// Shared factory (infrastructure/internalApiClient.ts) — see Finding 6/10 in
// /docs/audits/PHASE-02-10-14-CODE-REVIEW-FINDINGS.md. 8s timeout kept as-is (deliberately
// longer than the admin-console GMS/DMS clients): this is a single hop in an
// interactive redirect chain, not the token-issuance critical path those two
// are on. `requireData: true` preserves this call's historically stricter
// contract — the two admin clients fall back to returning the whole envelope
// when `data` is absent, but this path always expects a concrete payload
// (a minted session, a revoked-count) and previously threw if it got none.
const client = createInternalApiClient({
  serviceLabel: 'GMS',
  baseUrl: () => IDP_CONFIG.gms.apiBase,
  getApiKey: () => IDP_CONFIG.gms.internalApiKey,
  timeoutMs: 8_000,
  notConfiguredMessage: 'GMS_INTERNAL_API_KEY is not configured',
  requireData: true,
  createError: (message) => new Error(message),
});

async function gmsRequest<T>(path: string, body: unknown, requestId?: string): Promise<T> {
  assertConfigured();
  // ONE id for both headers, resolved before the call (not two separate
  // `requestId || crypto.randomUUID()` expressions) — when requestId was
  // empty, evaluating the fallback twice used to mint DIFFERENT uuids for the
  // two header names, silently breaking the correlation they exist to
  // provide, in exactly the no-request-id case where correlation matters
  // most.
  const correlationId = requestId || crypto.randomUUID();
  return client.request<T>(path, { method: 'POST', body: JSON.stringify(body) }, correlationId);
}

/** Optional first-provisioning office pin for office-scoped roles. */
async function resolveOfficeId(email: string): Promise<number | null> {
  const { rows } = await idpPool.query<{ office_id: number }>(
    'SELECT office_id FROM idp_gms_user_office WHERE email = $1',
    [email],
  );
  return rows[0]?.office_id ?? null;
}

/** Ask GMS to provision or resolve the user and mint its own session. */
export async function mintGmsSession(identity: BridgeIdentity, requestId?: string): Promise<GmsSession> {
  const email = identity.email.toLowerCase();
  const [initialRoles, initialOfficeId] = await Promise.all([
    resolveGmsRoles(email, identity.groups),
    resolveOfficeId(email),
  ]);

  return gmsRequest<GmsSession>('/internal/sso/sessions', {
    email,
    givenName: identity.givenName,
    familyName: identity.familyName,
    initialRoles,
    initialOfficeId,
  }, requestId);
}

/** Best-effort single-logout propagation to GMS's own session store. */
export async function revokeGmsSessionsByEmail(email: string): Promise<number> {
  if (!IDP_CONFIG.gms.enabled || !IDP_CONFIG.gms.internalApiKey) return 0;
  const result = await gmsRequest<{ revokedSessions: number }>('/internal/sso/sessions/revoke', {
    email: email.toLowerCase(),
  });
  return result.revokedSessions;
}
