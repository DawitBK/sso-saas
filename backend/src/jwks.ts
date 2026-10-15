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
import { logger } from './logging/logger.js';
import { getNumber } from './settings/store.js';
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
function retiredKeyOverlapSeconds(): number {
  // The larger of the configured defaults and the live settings, so raising a lifetime in the console lengthens the overlap at once.
  // Known limit: lowering a lifetime does not shrink it below the environment default, which is the safe direction (tokens issued
  // before the change are still verifiable); "Withdraw now" exists for the compromised-key case.
  return Math.max(IDP_CONFIG.ttl.idToken, IDP_CONFIG.ttl.accessToken, getNumber('ttl.idTokenSeconds'), getNumber('ttl.accessTokenSeconds')) + 300;
}

/**
 * Return all private JWKs oidc-provider should know about for `jwks.keys`:
 * every currently-active key, PLUS any retired key still inside its overlap
 * window. `is_active DESC` guarantees an active key always sorts first (so
 * oidc-provider — which signs with the first suitable key — never signs with
 * a retired one), while `created_at DESC` keeps the newest key of each group
 * first. Creates an initial key on first run.
 */
export async function loadSigningJwks(): Promise<PrivateJwk[]> {
  // `is_active` is selected purely for the invariant check below — the JWKS
  // itself only needs `jwk`.
  const { rows } = await pool.query<{ jwk: PrivateJwk; is_active: boolean }>(
    `SELECT jwk, is_active FROM idp_signing_keys
     WHERE is_active = TRUE OR retired_at > NOW() - ($1 || ' seconds')::interval
     ORDER BY is_active DESC, created_at DESC`,
    [retiredKeyOverlapSeconds()],
  );
  if (rows.length > 0) {
    // Exactly one key should ever be active (see rotateSigningKey). More than
    // one means rotation was bypassed — generateSigningKey() called directly,
    // or the table hand-edited, which /docs/audits/PLATFORM-MASTER-AUDIT-GUIDE.md:104-106
    // explicitly warns against. Which key signs then depends on row ordering
    // rather than intent. Loud, not fatal: the estate keeps working.
    const activeCount = rows.filter((r) => r.is_active).length;
    if (activeCount > 1) {
      logger.error(
        { activeCount },
        '[idp:jwks:ALERT] more than one signing key is marked is_active — rotation was bypassed or idp_signing_keys was hand-edited. Exactly one key should be active; the newest is being used to sign.',
      );
    }
    return rows.map((r) => r.jwk);
  }

  const jwk = await generateSigningKey();
  return [jwk];
}

export interface SigningKeyInfo {
  kid: string;
  is_active: boolean;
  created_at: string;
  retired_at: string | null;
  /**
   * Whether this key is still in the published JWKS right now — i.e. whether
   * relying parties still accept tokens signed with it. "Retired" alone does
   * not answer that: a key stays published for the overlap window (retiredKeyOverlapSeconds)
   * after retirement so in-flight tokens survive. The admin console needs the
   * distinction to show an honest status and to offer withdrawal only where it
   * would actually do something.
   */
  published: boolean;
}

export async function listSigningKeys(): Promise<SigningKeyInfo[]> {
  const { rows } = await pool.query<SigningKeyInfo>(
    `SELECT kid, is_active, created_at, retired_at,
            (is_active OR retired_at > NOW() - ($1 || ' seconds')::interval) AS published
       FROM idp_signing_keys
      ORDER BY created_at DESC`,
    [retiredKeyOverlapSeconds()],
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

/** What identifies the set of keys the provider should hold: which are published, and which one signs (the first, see loadSigningJwks). */
export function keySetSignature(jwks: Array<{ kid?: unknown }>): string {
  return jwks.map((k) => String(k.kid ?? '')).join(',');
}

/**
 * Keep this process's keystore in step with the table, without a restart.
 *
 * Two things change the table behind a running process's back: another SSO process (or a hand-run script) rotating or retiring a key, and
 * time itself, because a retired key stays published only for the overlap window and then must stop being published. Both left this
 * process serving and signing with the keys it loaded at boot until it restarted. Every REFRESH_MS the set is re-read (one small query) and
 * the provider is re-initialised only when the set of key ids, or which one signs, differs from what it holds.
 */
const KEY_REFRESH_MS = 30_000;
let keyTimer: NodeJS.Timeout | null = null;

/** Injectable for the test; production uses the real loader and reloader. */
export interface KeyRefreshDeps {
  load: () => Promise<Array<{ kid?: unknown }>>;
  reload: (provider: Provider) => Promise<void>;
  everyMs: number;
}

export function startSigningKeyRefresh(
  provider: Provider,
  initial?: PrivateJwk[],
  deps: KeyRefreshDeps = { load: loadSigningJwks, reload: reloadProviderKeys, everyMs: KEY_REFRESH_MS },
): void {
  if (keyTimer) return;
  let applied = initial ? keySetSignature(initial) : null;
  keyTimer = setInterval(() => {
    void (async () => {
      try {
        const jwks = await deps.load();
        const signature = keySetSignature(jwks);
        if (applied === null) {
          applied = signature;
          return;
        }
        if (signature !== applied) {
          await deps.reload(provider);
          logger.info({ before: applied, after: signature }, '[idp:jwks] the signing key set changed in the database; this process now serves and signs with the new set');
          applied = signature;
        }
      } catch (err) {
        // A failed read keeps the keys already loaded; the next tick tries again.
        logger.warn({ err }, '[idp:jwks] could not refresh the signing keys');
      }
    })();
  }, deps.everyMs);
  keyTimer.unref();
}

export function stopSigningKeyRefresh(): void {
  if (keyTimer) clearInterval(keyTimer);
  keyTimer = null;
}

/**
 * Stop this key being used AND stop publishing it (live immediately — see
 * reloadProviderKeys). Refuses the current signing key: the estate must always
 * keep one. That check is only correct because every rotate/retire reloads the
 * live process from the DB straight after writing, so "DB's newest active row"
 * and "what the process is actually signing with" never drift apart.
 *
 * WHY THIS HANDLES TWO CASES, NOT ONE
 *
 * It used to only demote `is_active = TRUE` rows. Under the invariant this
 * module enforces — rotateSigningKey demotes every active row before inserting
 * the new one, so exactly one key is ever active — the only active key is
 * always the current one, which the guard above refuses. The function could
 * therefore never succeed: every call returned either "rotate first" or "not
 * found or already retired". It was unreachable in practice, which is why the
 * admin console had no button for it, which is why nobody noticed.
 *
 * The operation an operator actually needs is the second case: a key that was
 * rotated out ten minutes ago is still published in the JWKS for
 * the overlap window (retiredKeyOverlapSeconds) so tokens signed just before the rotation keep
 * verifying. That grace window is correct for a routine rotation and exactly
 * wrong when the key leaked — until now there was no way to withdraw it early,
 * so a compromised key stayed trusted by every relying party for the rest of
 * the window. Backdating `retired_at` past the overlap drops it out of
 * loadSigningJwks() on the next reload, which the caller performs immediately.
 *
 * The cost is real and is the caller's to explain: any token still signed with
 * that key stops verifying at once, so those users must sign in again. That is
 * the point.
 */
export async function retireSigningKey(kid: string): Promise<{ ok: boolean; error?: string }> {
  const { rows } = await pool.query<{ kid: string }>(
    'SELECT kid FROM idp_signing_keys WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1',
  );
  if (rows[0]?.kid === kid) return { ok: false, error: 'Cannot retire the current signing key — rotate first.' };

  // Case 1: a stray extra active row (rotation was bypassed — loadSigningJwks
  // logs [idp:jwks:ALERT] when it sees this). Demote it.
  const demoted = await pool.query(
    'UPDATE idp_signing_keys SET is_active = FALSE, retired_at = NOW() WHERE kid = $1 AND is_active = TRUE',
    [kid],
  );
  if ((demoted.rowCount ?? 0) > 0) return { ok: true };

  // Case 2: already retired but still inside its publication window. Backdate
  // it clear of the overlap so it leaves the JWKS on the reload that follows.
  const withdrawn = await pool.query(
    `UPDATE idp_signing_keys
        SET retired_at = NOW() - (($1::bigint + 60) || ' seconds')::interval
      WHERE kid = $2
        AND is_active = FALSE
        AND retired_at > NOW() - ($1 || ' seconds')::interval`,
    [retiredKeyOverlapSeconds(), kid],
  );
  if ((withdrawn.rowCount ?? 0) > 0) return { ok: true };

  return { ok: false, error: 'Key not found, or already withdrawn from the JWKS.' };
}

/**
 * Generate and persist a new active RS256 signing key WITHOUT touching any
 * existing one. First-run bootstrap only — see rotateSigningKey() for the
 * operation the admin console should call.
 *
 * Left exported for loadSigningJwks()'s empty-table path. Calling this on a
 * populated table leaves two rows with is_active = TRUE, which is not a state
 * the rest of this module is written for.
 */
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

/**
 * Rotate: retire every currently-active key and install a new active one,
 * atomically. This is what "rotate" is supposed to mean and what the admin
 * console must call.
 *
 * WHY THIS EXISTS: the console's rotate button called generateSigningKey()
 * directly, which only ever INSERTs `is_active = TRUE` and never demotes the
 * previous key. Three clicks left three active keys. That breaks the model
 * /docs/operations/PLATFORM-SECRETS-AND-DATA-INTEGRITY-GUIDE.md:103-111 documents and that the
 * rest of this file assumes — "rotating a signing key keeps the old one
 * published in the public key list for an overlap window", i.e. exactly ONE
 * active signing key plus zero or more retired-but-published ones. With
 * several actives, `retireSigningKey`'s "refuse to retire the current key"
 * guard protects only the newest, `signing_keys_active` in /metrics climbs
 * without bound, and which key actually signs depends on row ordering.
 *
 * Setting retired_at = NOW() on the outgoing key is what keeps it published for
 * the overlap window (retiredKeyOverlapSeconds), so tokens signed a moment before the rotation
 * still verify for their natural lifetime.
 */
export async function rotateSigningKey(): Promise<PrivateJwk> {
  const kid = crypto.randomUUID();
  const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
  const jwk: PrivateJwk = {
    ...(await exportJWK(privateKey)),
    kid,
    use: 'sig',
    alg: 'RS256',
  };

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Serialize concurrent rotations so two admins clicking at once cannot both
    // demote-then-insert and end up with two actives again.
    await client.query(`SELECT pg_advisory_xact_lock(hashtext('idp_signing_key_rotate')::bigint)`);
    await client.query(
      `UPDATE idp_signing_keys SET is_active = FALSE, retired_at = NOW() WHERE is_active = TRUE`,
    );
    await client.query(
      `INSERT INTO idp_signing_keys (kid, jwk, is_active) VALUES ($1, $2, TRUE)`,
      [kid, JSON.stringify(jwk)],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
  return jwk;
}
