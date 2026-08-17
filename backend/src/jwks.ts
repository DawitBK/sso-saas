/**
 * JWKS signing-key management — persisted in Postgres (`idp_signing_keys`).
 *
 * Keys are RS256/RSA-2048, generated once and reused across restarts and
 * instances (the scaffold generated an ephemeral key on every boot, which broke
 * token verification after a restart). oidc-provider receives the private JWKs
 * and publishes the public halves at /.well-known/jwks.json with `kid`.
 *
 * Rotation (Phase 9): insert a new active key, keep the old one in the JWKS for
 * an overlap window ≥ max token lifetime, then set retired_at. `use: 'sig'`.
 */

import { exportJWK, generateKeyPair } from 'jose';
import type Provider from 'oidc-provider';
import { pool } from './db/pool.js';
import { IDP_CONFIG } from './config.js';
import crypto from 'node:crypto';

export interface PrivateJwk extends Record<string, unknown> {
  kid: string;
  alg: string;
  use: string;
}

/**
 * How long a retired key must stay published in the JWKS purely for
 * verification (never for new signing) after `retired_at`. Must be at least
 * the longest-lived token this key could have signed, or an id_token issued
 * moments before retirement would fail verification immediately instead of
 * riding out its natural TTL. A safety margin is added on top of the raw TTL.
 */
const RETIRED_KEY_OVERLAP_SECONDS = Math.max(IDP_CONFIG.ttl.idToken, IDP_CONFIG.ttl.accessToken) + 300;

/**
 * Return all private JWKs oidc-provider should know about for `jwks.keys`:
 * every currently-active key, PLUS any retired key still inside its overlap
 * window. `is_active DESC` guarantees an active key always sorts first (so
 * oidc-provider — which signs with the first suitable key — never signs with
 * a retired one), while `created_at DESC` keeps the newest key of each group
 * first. Creates an initial key on first run.
 */
export async function loadSigningJwks(): Promise<PrivateJwk[]> {
  const { rows } = await pool.query<{ jwk: PrivateJwk }>(
    `SELECT jwk FROM idp_signing_keys
     WHERE is_active = TRUE OR retired_at > NOW() - ($1 || ' seconds')::interval
     ORDER BY is_active DESC, created_at DESC`,
    [RETIRED_KEY_OVERLAP_SECONDS],
  );
  if (rows.length > 0) return rows.map((r) => r.jwk);

  const jwk = await generateSigningKey();
  return [jwk];
}

export interface SigningKeyInfo {
  kid: string;
  is_active: boolean;
  created_at: string;
  retired_at: string | null;
}

export async function listSigningKeys(): Promise<SigningKeyInfo[]> {
  const { rows } = await pool.query<SigningKeyInfo>(
    'SELECT kid, is_active, created_at, retired_at FROM idp_signing_keys ORDER BY created_at DESC',
  );
  return rows;
}

/**
 * Re-read active keys from Postgres and push them into the RUNNING oidc-provider
 * instance — this is what makes rotate/retire take effect without a restart.
 *
 * oidc-provider (v8) has no public "reload the JWKS" API: `initializeKeystore`
 * runs once in the Provider constructor and stashes the keystore + /jwks response
 * on the provider's private per-instance map. We call that same initializer again
 * on the live provider — every place oidc-provider signs or serves /jwks re-reads
 * that map per-request (verified in lib/models/id_token.js and
 * lib/actions/jwks.js), so this is not a stale/cached read.
 */
export async function reloadProviderKeys(provider: Provider): Promise<void> {
  const jwks = await loadSigningJwks();
  // A non-literal specifier so TS doesn't try (and fail) to resolve type
  // declarations for this internal path — see the doc comment above for why
  // this deep import into oidc-provider is necessary.
  const modulePath = 'oidc-provider/lib/helpers/initialize_keystore.js';
  const { default: initializeKeystore } = (await import(modulePath)) as { default: (jwks: { keys: PrivateJwk[] }) => void };
  initializeKeystore.call(provider, { keys: jwks });
}

/**
 * Retire an old key (live immediately — see reloadProviderKeys). Refuses to
 * retire the newest active key — the estate must always keep a signing key.
 * This check is only correct because every rotate/retire reloads the live
 * process from the DB immediately after writing, so "DB's newest active row"
 * and "what the process is actually signing with" never drift apart.
 */
export async function retireSigningKey(kid: string): Promise<{ ok: boolean; error?: string }> {
  const { rows } = await pool.query<{ kid: string }>(
    'SELECT kid FROM idp_signing_keys WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1',
  );
  if (rows[0]?.kid === kid) return { ok: false, error: 'Cannot retire the current signing key — rotate first.' };
  const res = await pool.query(
    'UPDATE idp_signing_keys SET is_active = FALSE, retired_at = NOW() WHERE kid = $1 AND is_active = TRUE',
    [kid],
  );
  return (res.rowCount ?? 0) > 0 ? { ok: true } : { ok: false, error: 'Key not found or already retired.' };
}

/** Generate, persist, and return a new active RS256 signing key. */
export async function generateSigningKey(): Promise<PrivateJwk> {
  const kid = crypto.randomUUID();
  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const jwk: PrivateJwk = {
    ...(await exportJWK(privateKey)),
    kid,
    use: 'sig',
    alg: 'RS256',
  };
  await pool.query(
    `INSERT INTO idp_signing_keys (kid, jwk, is_active) VALUES ($1, $2, TRUE)`,
    [kid, JSON.stringify(jwk)],
  );
  return jwk;
}
