/**
 * The relying-party registry as the console manages it: details, addresses, on/off, secret rotation, usage.
 *
 * Which clients exist is decided by the code (config.ts clientSeed + portal/catalog.ts + the role code): adding a system is a
 * deployment, not a form. What the console manages is what an operator legitimately changes in place: the addresses, whether the
 * client is switched on, and its secret. Every change here reaches oidc-provider on the NEXT request, because clients are read
 * through the adapter (adapters/postgres.ts) rather than frozen at boot.
 *
 * The secret never leaves the server except once, in the response to a rotation.
 */
import crypto from 'node:crypto';
import { DEV_DEFAULT_CLIENT_SECRETS, IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { PA_IDS_SQL } from '../auth/platform-admin.js';
import { sameUriSet } from './clients.js';

/** Plain-language facts about each seeded client that the database does not hold. */
export const CLIENT_FACTS: Record<string, { pattern: string; rolesScope: string | null; critical: string | null; secretNote: string | null }> = {
  edams: {
    pattern: 'OpenID Connect client. DMS signs people in itself: it exchanges the code with SSO and reads the person’s roles from the token.',
    rolesScope: 'edams_roles',
    critical: null,
    secretNote: 'DMS keeps its own copy of this secret (OIDC_CLIENT_SECRET in the .env.production file of DMS). After a rotation, put the new value there and restart DMS; until then signing in to DMS fails.',
  },
  gms: {
    pattern: 'Token bridge. SSO signs GMS in through GMS’s own internal API and hands the browser over through the same-origin gateway.',
    rolesScope: 'gms_roles',
    critical: null,
    secretNote: 'GMS does not hold this secret: the bridge inside SSO reads it from the database and uses a new one within seconds. Nothing else needs updating.',
  },
  portal: {
    pattern: 'The SSO portal and admin console themselves. They learn who is signed in by being a client of this service.',
    rolesScope: null,
    critical: 'The portal and the admin console sign in through this client. Its addresses are derived from the service address and it cannot be switched off: an error here would lock every administrator out of the console.',
    secretNote: null,
  },
};

export interface ClientUsage {
  activeGrants: number;
  activeRefreshTokens: number;
  activeAccessTokens: number;
  lastTokenIssuedAt: string | null;
}

export interface ClientDetails {
  clientId: string;
  name: string;
  active: boolean;
  scopes: string[];
  grantTypes: string[];
  authMethod: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  /** The addresses the environment configuration says it should have, and whether the stored ones differ. */
  configuredRedirectUris: string[];
  configuredPostLogoutRedirectUris: string[];
  urisDrift: boolean;
  /** Secrets still holding a well-known development value are a defect to fix before production. */
  secretIsDevDefault: boolean;
  secretRotatedAt: string | null;
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
  pattern: string;
  rolesScope: string | null;
  critical: string | null;
  secretNote: string | null;
  usage: ClientUsage;
  entitledUsers: number | null;
}

interface Row {
  client_id: string;
  client_secret: string;
  name: string;
  is_active: boolean;
  scope: string | null;
  grant_types: string[];
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  secret_rotated_at: Date | null;
  created_at: Date;
  updated_at: Date;
  updated_by: string;
}

const SEEDED = (): string[] => IDP_CONFIG.clientSeed.map((c) => c.client_id);

export function isManagedClient(clientId: string): boolean {
  return SEEDED().includes(clientId);
}

async function usageFor(clientId: string): Promise<ClientUsage> {
  const { rows } = await pool.query<{ grants: string; refresh: string; access: string; last_issued: string | null }>(
    `SELECT
       COUNT(*) FILTER (WHERE kind = 'Grant') AS grants,
       COUNT(*) FILTER (WHERE kind = 'RefreshToken') AS refresh,
       COUNT(*) FILTER (WHERE kind = 'AccessToken') AS access,
       MAX(CASE WHEN kind = 'AccessToken' THEN (payload->>'iat')::bigint END) AS last_issued
     FROM oidc_artifacts
     WHERE kind IN ('Grant', 'RefreshToken', 'AccessToken')
       AND payload->>'clientId' = $1
       AND (expires_at IS NULL OR expires_at > NOW())
       AND coalesce(payload->>'accountId', '') NOT IN ${PA_IDS_SQL}`,
    [clientId],
  );
  const r = rows[0];
  return {
    activeGrants: Number(r?.grants ?? 0),
    activeRefreshTokens: Number(r?.refresh ?? 0),
    activeAccessTokens: Number(r?.access ?? 0),
    lastTokenIssuedAt: r?.last_issued ? new Date(Number(r.last_issued) * 1000).toISOString() : null,
  };
}

function toDetails(row: Row, usage: ClientUsage, entitledUsers: number | null): ClientDetails {
  const seed = IDP_CONFIG.clientSeed.find((c) => c.client_id === row.client_id);
  const facts = CLIENT_FACTS[row.client_id] ?? { pattern: 'Registered client.', rolesScope: null, critical: null, secretNote: null };
  const configuredRedirect = seed?.redirect_uris ?? [];
  const configuredLogout = seed?.post_logout_redirect_uris ?? [];
  return {
    clientId: row.client_id,
    name: row.name,
    active: row.is_active,
    scopes: (row.scope ?? '').split(/\s+/).filter(Boolean),
    grantTypes: row.grant_types?.length ? row.grant_types : ['authorization_code', 'refresh_token'],
    authMethod: 'client_secret_post',
    redirectUris: row.redirect_uris,
    postLogoutRedirectUris: row.post_logout_redirect_uris ?? [],
    configuredRedirectUris: configuredRedirect,
    configuredPostLogoutRedirectUris: configuredLogout,
    urisDrift: !sameUriSet(row.redirect_uris, configuredRedirect) || !sameUriSet(row.post_logout_redirect_uris ?? [], configuredLogout),
    secretIsDevDefault: DEV_DEFAULT_CLIENT_SECRETS.includes(row.client_secret),
    secretRotatedAt: row.secret_rotated_at ? new Date(row.secret_rotated_at).toISOString() : null,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    updatedBy: row.updated_by === 'platform' ? 'Platform administrator' : row.updated_by,
    pattern: facts.pattern,
    rolesScope: facts.rolesScope,
    critical: facts.critical,
    secretNote: facts.secretNote,
    usage,
    entitledUsers,
  };
}

const SELECT = `SELECT client_id, client_secret, name, is_active, scope, grant_types, redirect_uris, post_logout_redirect_uris,
                       secret_rotated_at, created_at, updated_at, updated_by
                  FROM idp_clients`;

export async function listClientDetails(entitled: (clientId: string) => Promise<number | null>): Promise<ClientDetails[]> {
  const { rows } = await pool.query<Row>(`${SELECT} WHERE client_id = ANY($1::text[])`, [SEEDED()]);
  const byId = new Map(rows.map((r) => [r.client_id, r]));
  const out: ClientDetails[] = [];
  // In the order the deployment lists them, so the page does not reshuffle.
  for (const id of SEEDED()) {
    const row = byId.get(id);
    if (row) out.push(toDetails(row, await usageFor(id), await entitled(id)));
  }
  return out;
}

export async function getClientDetails(clientId: string, entitled: (clientId: string) => Promise<number | null>): Promise<ClientDetails | null> {
  if (!isManagedClient(clientId)) return null;
  const { rows } = await pool.query<Row>(`${SELECT} WHERE client_id = $1`, [clientId]);
  return rows[0] ? toDetails(rows[0], await usageFor(clientId), await entitled(clientId)) : null;
}

export async function updateClientUris(
  clientId: string,
  uris: { redirect: string[]; logout: string[] },
  actor: string,
): Promise<{ before: { redirect: string[]; logout: string[] }; after: { redirect: string[]; logout: string[] } }> {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    const { rows } = await db.query<{ redirect_uris: string[]; post_logout_redirect_uris: string[] }>(
      'SELECT redirect_uris, post_logout_redirect_uris FROM idp_clients WHERE client_id = $1 FOR UPDATE',
      [clientId],
    );
    if (!rows[0]) throw new Error('client not found');
    await db.query(
      'UPDATE idp_clients SET redirect_uris = $2, post_logout_redirect_uris = $3, updated_at = NOW(), updated_by = $4 WHERE client_id = $1',
      [clientId, uris.redirect, uris.logout, actor],
    );
    await db.query('COMMIT');
    return { before: { redirect: rows[0].redirect_uris, logout: rows[0].post_logout_redirect_uris ?? [] }, after: uris };
  } catch (err) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    db.release();
  }
}

/** Switch a client on or off. Switching off also ends everything already issued to it, so the effect is immediate and total. */
export async function setClientActive(clientId: string, active: boolean, actor: string): Promise<{ revokedArtifacts: number }> {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    const r = await db.query('UPDATE idp_clients SET is_active = $2, updated_at = NOW(), updated_by = $3 WHERE client_id = $1', [clientId, active, actor]);
    if (r.rowCount === 0) throw new Error('client not found');
    let revoked = 0;
    if (!active) {
      const del = await db.query(
        `DELETE FROM oidc_artifacts
          WHERE kind IN ('Grant', 'AccessToken', 'RefreshToken', 'AuthorizationCode', 'DeviceCode', 'Interaction')
            AND payload->>'clientId' = $1`,
        [clientId],
      );
      revoked = del.rowCount ?? 0;
    }
    await db.query('COMMIT');
    return { revokedArtifacts: revoked };
  } catch (err) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    db.release();
  }
}

/** A fresh secret (48 random bytes, base64url). The only place it is ever returned. */
export function generateClientSecret(): string {
  return crypto.randomBytes(48).toString('base64url');
}

export async function rotateClientSecret(clientId: string, actor: string): Promise<string> {
  const secret = generateClientSecret();
  const r = await pool.query(
    'UPDATE idp_clients SET client_secret = $2, secret_rotated_at = NOW(), updated_at = NOW(), updated_by = $3 WHERE client_id = $1',
    [clientId, secret, actor],
  );
  if (r.rowCount === 0) throw new Error('client not found');
  return secret;
}
