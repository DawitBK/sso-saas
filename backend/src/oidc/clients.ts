/**
 * Relying-party (OIDC client) registry, backed by `idp_clients`.
 * Seeds the configured clients on first boot, then loads them for oidc-provider.
 * Adding a future app = insert a row here (config-only onboarding for OIDC apps).
 */

import type { ClientMetadata } from 'oidc-provider';
import { DEV_DEFAULT_CLIENT_SECRETS, IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';

/** True when two address lists hold the same addresses, ignoring order and repeats. */
export function sameUriSet(a: readonly string[] | null | undefined, b: readonly string[] | null | undefined): boolean {
  const x = new Set(a ?? []);
  const y = new Set(b ?? []);
  return x.size === y.size && [...x].every((v) => y.has(v));
}

/**
 * Every client is registered as a CONFIDENTIAL client authenticating with
 * `client_secret_post` (see loadClients). Public clients (token_endpoint_auth_method
 * `none`, e.g. a browser-only app using PKCE alone) are NOT supported; supporting one
 * needs a code change here and a nullable secret column.
 */
export const SUPPORTED_TOKEN_AUTH_METHOD = 'client_secret_post';

/**
 * Insert configured clients if missing (idempotent; never overwrites a real edit).
 * Exception: if the DB still holds one of the well-known dev-placeholder secrets
 * (e.g. the configured env var was missing on a very first boot), overwrite the
 * secret AND the redirect/logout URIs from the current config. A stuck dev row
 * is a bootstrap bug, not an intentional admin edit, and otherwise leaves local
 * port migrations stranded behind stale client metadata.
 *
 * CONSEQUENCE, which is easy to miss: once a row holds a real secret, editing
 * EDAMS_REDIRECT_URIS / EDAMS_LOGOUT_URIS / GMS_REDIRECT_URIS / GMS_LOGOUT_URIS (or
 * IDP_ISSUER, which the portal client's addresses derive from) in an env file changes
 * NOTHING for that client. The mismatch is no longer silent: seedClients() logs a
 * warning naming the client and both lists on every boot, and the supported way to
 * apply the new addresses is `npm run client:uris[:mirror|:prod]` (scripts/
 * update-client-redirect-uris.ts: dry run by default, `--apply` to write), followed
 * by an SSO backend restart (oidc-provider loads the client list at boot).
 */
export async function seedClients(): Promise<void> {
  for (const c of IDP_CONFIG.clientSeed) {
    await pool.query(
      `INSERT INTO idp_clients (client_id, client_secret, redirect_uris, post_logout_redirect_uris, name, scope)
       VALUES ($1, $2, $3, $4, $5, $7)
       ON CONFLICT (client_id) DO UPDATE
         SET client_secret = EXCLUDED.client_secret,
             redirect_uris = EXCLUDED.redirect_uris,
             post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
             name = EXCLUDED.name
         WHERE idp_clients.client_secret = ANY($6)`,
      [c.client_id, c.client_secret, c.redirect_uris, c.post_logout_redirect_uris ?? [], c.name, DEV_DEFAULT_CLIENT_SECRETS, c.scope ?? null],
    );

    /**
     * The scope allowlist (P1-2) is synced separately from the block above.
     *
     * That block deliberately only overwrites a row still holding a dev-default
     * secret — it must never clobber a real admin edit. But `scope` is not an
     * admin-editable field; it is a code-level statement of which claims a
     * relying party is entitled to, and it has to reach rows that were seeded
     * before the column existed, whose secrets are real. Only filled when NULL or
     * empty, so an operator who deliberately narrowed a client's scope in the DB
     * keeps their narrowing.
     */
    if (c.scope) {
      await pool.query(
        `UPDATE idp_clients SET scope = $2, updated_at = NOW()
          WHERE client_id = $1 AND (scope IS NULL OR scope = '')`,
        [c.client_id, c.scope],
      );
    }

    // Say so when the stored addresses are not the configured ones (see the note above).
    const { rows } = await pool.query<{ redirect_uris: string[]; post_logout_redirect_uris: string[] | null }>(
      'SELECT redirect_uris, post_logout_redirect_uris FROM idp_clients WHERE client_id = $1',
      [c.client_id],
    );
    const stored = rows[0];
    if (
      stored &&
      (!sameUriSet(stored.redirect_uris, c.redirect_uris) ||
        !sameUriSet(stored.post_logout_redirect_uris, c.post_logout_redirect_uris ?? []))
    ) {
      logger.warn(
        {
          clientId: c.client_id,
          storedRedirectUris: stored.redirect_uris,
          configuredRedirectUris: c.redirect_uris,
          storedPostLogoutUris: stored.post_logout_redirect_uris ?? [],
          configuredPostLogoutUris: c.post_logout_redirect_uris ?? [],
        },
        `[idp:clients:WARN] client "${c.client_id}": the redirect addresses stored in idp_clients differ from the env configuration. ` +
          'Editing *_REDIRECT_URIS / *_LOGOUT_URIS does not update an existing client whose secret is no longer a dev default. ' +
          'Review with `npm run client:uris` (add :mirror or :prod for those environments) and apply with --apply, then restart SSO.',
      );
    }
  }
}

interface ClientRow {
  client_id: string;
  client_secret: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  grant_types: string[];
  scope: string | null;
}

/** One idp_clients row in the shape oidc-provider expects. */
function toMetadata(r: ClientRow): ClientMetadata {
  return {
    client_id: r.client_id,
    client_secret: r.client_secret,
    redirect_uris: r.redirect_uris,
    post_logout_redirect_uris: r.post_logout_redirect_uris ?? [],
    grant_types: r.grant_types?.length ? r.grant_types : ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: SUPPORTED_TOKEN_AUTH_METHOD,
    // P1-2. Omitted (not set to '') when NULL: oidc-provider treats an absent
    // `scope` as "no restriction", which is exactly the pre-P1-2 behaviour, so a
    // database that has not had migration 012 applied keeps working instead of
    // failing every authorize request with invalid_scope. An empty string would
    // instead forbid every scope including `openid` and break all logins.
    ...(r.scope ? { scope: r.scope } : {}),
  };
}

const SERVED_COLUMNS = 'client_id, client_secret, redirect_uris, post_logout_redirect_uris, grant_types, scope';

/**
 * Load active clients in the shape oidc-provider expects.
 * Only the clients this deployment seeds are served: a retired system's row (retail-os, MRS ...) keeps its secret and
 * redirect URIs in the table but must not be able to start an authorization flow.
 */
export async function loadClients(): Promise<ClientMetadata[]> {
  const { rows } = await pool.query<ClientRow>(
    `SELECT ${SERVED_COLUMNS} FROM idp_clients WHERE is_active = TRUE AND client_id = ANY($1::text[])`,
    [IDP_CONFIG.clientSeed.map((c) => c.client_id)],
  );
  return rows.map(toMetadata);
}

/**
 * One client, read at the moment oidc-provider asks for it (the adapter's `Client` model, adapters/postgres.ts).
 *
 * This is what makes the console's Clients page live. oidc-provider freezes a `clients: [...]` list given at start-up for the life
 * of the process, so editing a redirect address or switching a client off would only have taken effect after a restart. A client it
 * finds through the adapter is looked up on every request and rebuilt whenever its stored metadata changes, so an edit applies to
 * the very next sign-in. Same rule as loadClients: seeded, active clients only.
 */
export async function findClientMetadata(clientId: string): Promise<ClientMetadata | undefined> {
  if (!IDP_CONFIG.clientSeed.some((c) => c.client_id === clientId)) return undefined;
  const { rows } = await pool.query<ClientRow>(`SELECT ${SERVED_COLUMNS} FROM idp_clients WHERE client_id = $1 AND is_active = TRUE`, [clientId]);
  return rows[0] ? toMetadata(rows[0]) : undefined;
}
