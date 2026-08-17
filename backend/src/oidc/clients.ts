/**
 * Relying-party (OIDC client) registry, backed by `idp_clients`.
 * Seeds the configured clients on first boot, then loads them for oidc-provider.
 * Adding a future app = insert a row here (config-only onboarding for OIDC apps).
 */

import type { ClientMetadata } from 'oidc-provider';
import { DEV_DEFAULT_CLIENT_SECRETS, IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';

/**
 * Insert configured clients if missing (idempotent; never overwrites a real edit).
 * Exception: if the DB still holds one of the well-known dev-placeholder secrets
 * (e.g. the configured env var was missing on a very first boot), overwrite the
 * secret AND the redirect/logout URIs from the current config. A stuck dev row
 * is a bootstrap bug, not an intentional admin edit, and otherwise leaves local
 * port migrations stranded behind stale client metadata.
 */
export async function seedClients(): Promise<void> {
  for (const c of IDP_CONFIG.clientSeed) {
    await pool.query(
      `INSERT INTO idp_clients (client_id, client_secret, redirect_uris, post_logout_redirect_uris, name)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (client_id) DO UPDATE
         SET client_secret = EXCLUDED.client_secret,
             redirect_uris = EXCLUDED.redirect_uris,
             post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
             name = EXCLUDED.name
         WHERE idp_clients.client_secret = ANY($6)`,
      [c.client_id, c.client_secret, c.redirect_uris, c.post_logout_redirect_uris ?? [], c.name, DEV_DEFAULT_CLIENT_SECRETS],
    );
  }
}

/** Load active clients in the shape oidc-provider expects. */
export async function loadClients(): Promise<ClientMetadata[]> {
  const { rows } = await pool.query<{
    client_id: string;
    client_secret: string;
    redirect_uris: string[];
    post_logout_redirect_uris: string[];
    grant_types: string[];
  }>(`SELECT client_id, client_secret, redirect_uris, post_logout_redirect_uris, grant_types
      FROM idp_clients WHERE is_active = TRUE`);

  return rows.map((r) => ({
    client_id: r.client_id,
    client_secret: r.client_secret,
    redirect_uris: r.redirect_uris,
    post_logout_redirect_uris: r.post_logout_redirect_uris ?? [],
    grant_types: r.grant_types?.length ? r.grant_types : ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
  }));
}
