/**
 * The signed licence token (docs/operations/PLATFORM-LICENSING.md section 4): a compact JWS, RS256, header `typ: "kcms-license+jwt"` and the signing key's `kid`.
 * It is signed with the DEDICATED licence key when LICENSE_SIGNING_KEY_FILE is set (a PEM kept outside the repository; consumers pin its public half in
 * LICENSE_TRUST_PUBLIC_KEYS, section 9), otherwise with the SAME key oidc-provider signs id_tokens with (the active row of idp_signing_keys, published at /jwks).
 *
 * There is deliberately NO `exp` claim: the licence's own dates are the expiry, and a consumer must not reject a token for its age (it keeps
 * enforcing the last token it verified even when SSO is down for weeks). The token holds no secret; it is served unauthenticated.
 *
 * A consumer verifies the signature against the JWKS, the `typ`, `iss`, `aud === "license:<its system>"` and `sys`, and ignores a token whose
 * `ver` is lower than the one it holds. After a signing-key rotation the next fetch is signed with the new key. A consumer verifies a token when it
 * FETCHES it and then enforces that token's own dates, so a token it already accepted keeps working after the old key leaves the JWKS.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { SignJWT, calculateJwkThumbprint, exportJWK, importJWK, importPKCS8, type JWK } from 'jose';
import { IDP_CONFIG } from '../config.js';
import { loadSigningJwks } from '../jwks.js';
import type { LicenseRecord } from './repository.js';

export const LICENSE_TOKEN_TYP = 'kcms-license+jwt';
export const licenseAudience = (system: string): string => `license:${system}`;

type KeyLike = Awaited<ReturnType<typeof importJWK>>;
const KEY_TTL_MS = 30_000;
let keyCache: { kid: string; key: KeyLike; at: number } | null = null;
const tokenCache = new Map<string, string>();

/** The dedicated licence key (LICENSE_SIGNING_KEY_FILE): re-read when the file changes, the kid is the public key's JWK thumbprint. */
let fileKeyCache: { path: string; mtimeMs: number; kid: string; key: KeyLike } | null = null;
async function dedicatedKey(path: string): Promise<{ kid: string; key: KeyLike }> {
  const mtimeMs = fs.statSync(path).mtimeMs;
  if (fileKeyCache && fileKeyCache.path === path && fileKeyCache.mtimeMs === mtimeMs) return fileKeyCache;
  const pem = fs.readFileSync(path, 'utf8');
  const key = await importPKCS8(pem, 'RS256');
  const publicJwk = await exportJWK(crypto.createPublicKey(pem));
  fileKeyCache = { path, mtimeMs, kid: await calculateJwkThumbprint(publicJwk), key };
  return fileKeyCache;
}

/** The key that signs right now: the dedicated licence key when configured, else the first one loadSigningJwks returns (active keys sort first), which is also the one oidc-provider uses. */
async function signingKey(): Promise<{ kid: string; key: KeyLike }> {
  if (IDP_CONFIG.licenseSigningKeyFile) return dedicatedKey(IDP_CONFIG.licenseSigningKeyFile);
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
  fileKeyCache = null;
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
  /** Deployment shapes this licence authorises (section 9); a consumer treats absent or empty as ['sso']. */
  modes: string[];
  /** One id per issued version of a licence: `<system>-v<version>`. */
  jti: string;
}

/** The claims a token for `record` carries (shared by the online signer and `npm run license:sign`). */
export function licenseClaims(record: LicenseRecord): Omit<LicenseTokenClaims, 'iss' | 'aud' | 'iat'> {
  return {
    sys: record.system,
    ver: record.version,
    jti: `${record.system}-v${record.version}`,
    customer: record.customer,
    expiresAt: record.expiresAt,
    graceDays: record.graceDays,
    warnDays: record.warnDays,
    maxUsers: record.maxUsers,
    modules: record.modules,
    modes: record.modes,
  };
}

/** Sign `record` with an explicit key and issuer (the offline signer; nothing here touches a database or the OIDC keys). */
export async function signLicenseTokenWith(record: LicenseRecord, key: KeyLike, kid: string, issuer: string): Promise<string> {
  return new SignJWT({ ...licenseClaims(record) })
    .setProtectedHeader({ alg: 'RS256', typ: LICENSE_TOKEN_TYP, kid })
    .setIssuer(issuer)
    .setAudience(licenseAudience(record.system))
    .setIssuedAt()
    .sign(key);
}

export async function signLicenseToken(record: LicenseRecord): Promise<string> {
  const { kid, key } = await signingKey();
  // One token per (system, version, key): a licence that has not changed answers with byte-identical tokens (and signing costs nothing).
  const cacheKey = `${record.system}:${record.version}:${kid}:${record.updatedAt}`;
  const hit = tokenCache.get(cacheKey);
  if (hit) return hit;
  const token = await signLicenseTokenWith(record, key, kid, IDP_CONFIG.issuer);
  if (tokenCache.size > 50) tokenCache.clear();
  tokenCache.set(cacheKey, token);
  return token;
}
