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

interface GmsInternalResponse<T> {
  success: boolean;
  data?: T;
  error?: { message?: string };
}

function assertConfigured(): void {
  if (!IDP_CONFIG.gms.enabled) throw new Error('GMS bridge is disabled (GMS_BRIDGE_ENABLED=false)');
  if (!IDP_CONFIG.gms.internalApiKey) throw new Error('GMS_INTERNAL_API_KEY is not configured');
  if (!IDP_CONFIG.gms.apiBase) throw new Error('GMS_API_BASE is not configured');
}

function internalUrl(path: string): string {
  return IDP_CONFIG.gms.apiBase.replace(/\/$/, '') + path;
}

async function gmsRequest<T>(path: string, body: unknown, requestId?: string): Promise<T> {
  assertConfigured();
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), 8_000);
  try {
    const response = await fetch(internalUrl(path), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-internal-api-key': IDP_CONFIG.gms.internalApiKey,
        'x-request-id': requestId || crypto.randomUUID(),
        'x-correlation-id': requestId || crypto.randomUUID(),
      },
      body: JSON.stringify(body),
      signal: abort.signal,
    });
    const payload = await response.json().catch(() => ({})) as GmsInternalResponse<T>;
    if (!response.ok || !payload.success || !payload.data) {
      throw new Error('GMS internal API request failed (' + response.status + '): ' + (payload.error?.message ?? 'unknown error'));
    }
    return payload.data;
  } finally {
    clearTimeout(timeout);
  }
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
