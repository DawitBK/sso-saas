/**
 * The signed licence token (docs/operations/PLATFORM-LICENSING.md section 4): a compact JWS, RS256, signed with the SAME key oidc-provider signs
 * id_tokens with (the active row of idp_signing_keys, published at /jwks), header `typ: "kcms-license+jwt"` and that key's `kid`.
 *
 * There is deliberately NO `exp` claim: the licence's own dates are the expiry, and a consumer must not reject a token for its age (it keeps
 * enforcing the last token it verified even when SSO is down for weeks). The token holds no secret; it is served unauthenticated.
 *
 * A consumer verifies the signature against the JWKS, the `typ`, `iss`, `aud === "license:<its system>"` and `sys`, and ignores a token whose
 * `ver` is lower than the one it holds. After a signing-key rotation the next fetch is signed with the new key. A consumer verifies a token when it
 * FETCHES it and then enforces that token's own dates, so a token it already accepted keeps working after the old key leaves the JWKS.
 */
import { SignJWT, importJWK, type JWK } from 'jose';
import { IDP_CONFIG } from '../config.js';
import { loadSigningJwks } from '../jwks.js';
import type { LicenseRecord } from './repository.js';

export const LICENSE_TOKEN_TYP = 'kcms-license+jwt';
export const licenseAudience = (system: string): string => `license:${system}`;

type KeyLike = Awaited<ReturnType<typeof importJWK>>;
const KEY_TTL_MS = 30_000;
let keyCache: { kid: string; key: KeyLike; at: number } | null = null;
const tokenCache = new Map<string, string>();

/** The key that signs right now: the first one loadSigningJwks returns (active keys sort first), which is also the one oidc-provider uses. */
async function signingKey(): Promise<{ kid: string; key: KeyLike }> {
  if (keyCache && Date.now() - keyCache.at < KEY_TTL_MS) return keyCache;
  const [jwk] = await loadSigningJwks();
  if (!jwk) throw new Error('no signing key available');
  const key = await importJWK(jwk as unknown as JWK, 'RS256');
  keyCache = { kid: String(jwk.kid), key, at: Date.now() };
  return keyCache;
}

/** Forget cached keys and tokens (tests; a key rotation is picked up within KEY_TTL_MS anyway). */
export function resetLicenseTokenCache(): void {
  keyCache = null;
  tokenCache.clear();
}

export interface LicenseTokenClaims {
  iss: string;
  aud: string;
  sys: string;
  ver: number;
  iat: number;
  customer: string;
  expiresAt: string | null;
  graceDays: number;
  warnDays: number;
  maxUsers: number | null;
  modules: string[] | null;
}

export async function signLicenseToken(record: LicenseRecord): Promise<string> {
  const { kid, key } = await signingKey();
  // One token per (system, version, key): a licence that has not changed answers with byte-identical tokens (and signing costs nothing).
  const cacheKey = `${record.system}:${record.version}:${kid}:${record.updatedAt}`;
  const hit = tokenCache.get(cacheKey);
  if (hit) return hit;
  const token = await new SignJWT({
    sys: record.system,
    ver: record.version,
    customer: record.customer,
    expiresAt: record.expiresAt,
    graceDays: record.graceDays,
    warnDays: record.warnDays,
    maxUsers: record.maxUsers,
    modules: record.modules,
  })
    .setProtectedHeader({ alg: 'RS256', typ: LICENSE_TOKEN_TYP, kid })
    .setIssuer(IDP_CONFIG.issuer)
    .setAudience(licenseAudience(record.system))
    .setIssuedAt()
    .sign(key);
  if (tokenCache.size > 50) tokenCache.clear();
  tokenCache.set(cacheKey, token);
  return token;
}
