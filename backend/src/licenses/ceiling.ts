/**
 * The "SSO ends on this date" note (owner decision 2026-10-21; docs/operations/PLATFORM-LICENSING.md section 10).
 *
 * With OFFLINE licences GMS and DMS hold a token signed on the owner's computer and trust only the owner's public key, so SSO cannot re-sign a
 * client licence to make it follow SSO's own expiry (that needs the private key on the server: licenses/follow.ts, used on the mirror). Instead SSO
 * publishes this small note, signed with its ordinary OIDC key (the active row of idp_signing_keys, published at /jwks, the key every client can
 * already fetch). A client verifies it against SSO's JWKS and takes the EARLIER of its own licence date and this one.
 *
 * Why that is safe without the owner's key: the note can only SHORTEN a licence. A forged or replayed note cannot extend anything (the client's own
 * offline-signed date is the hard backstop). It always uses the OIDC key, never LICENSE_SIGNING_KEY_FILE, so the JWKS a client already trusts for SSO
 * verifies it. Like the licence token it has no `exp` (a client keeps enforcing the last note it verified while SSO is down) and holds no secret.
 */
import { SignJWT, importJWK, type JWK } from 'jose';
import { IDP_CONFIG } from '../config.js';
import { loadSigningJwks } from '../jwks.js';
import type { LicenseRecord } from './repository.js';

export const CEILING_TOKEN_TYP = 'kcms-license-ceiling+jwt';
export const CEILING_AUDIENCE = 'license:ceiling';

type KeyLike = Awaited<ReturnType<typeof importJWK>>;
const KEY_TTL_MS = 30_000;
let keyCache: { kid: string; key: KeyLike; at: number } | null = null;
const tokenCache = new Map<string, string>();

export function resetCeilingCache(): void {
  keyCache = null;
  tokenCache.clear();
}

async function oidcKey(): Promise<{ kid: string; key: KeyLike }> {
  if (keyCache && Date.now() - keyCache.at < KEY_TTL_MS) return keyCache;
  const [jwk] = await loadSigningJwks();
  if (!jwk) throw new Error('no signing key available');
  const key = await importJWK(jwk as unknown as JWK, 'RS256');
  keyCache = { kid: String(jwk.kid), key, at: Date.now() };
  return keyCache;
}

/** The claims of the note for SSO's own licence `record`; `version` is never below the record's. */
export function ceilingClaims(record: LicenseRecord, version: number) {
  return {
    sys: 'sso',
    ver: version,
    jti: `sso-ceiling-v${version}`,
    customer: record.customer,
    expiresAt: record.expiresAt,
    graceDays: record.graceDays,
    warnDays: record.warnDays,
  };
}

/** Sign with an explicit key (tests). */
export async function signCeilingTokenWith(record: LicenseRecord, version: number, key: KeyLike, kid: string, issuer: string): Promise<string> {
  return new SignJWT({ ...ceilingClaims(record, version) })
    .setProtectedHeader({ alg: 'RS256', typ: CEILING_TOKEN_TYP, kid })
    .setIssuer(issuer)
    .setAudience(CEILING_AUDIENCE)
    .setIssuedAt()
    .sign(key);
}

/** The note for SSO's licence, signed with the OIDC signing key. One note per (version, key, change time): an unchanged licence answers with the same token. */
export async function signCeilingToken(record: LicenseRecord, ssoHighestVersion: number): Promise<string> {
  const version = Math.max(record.version, ssoHighestVersion);
  const { kid, key } = await oidcKey();
  const cacheKey = `${version}:${kid}:${record.updatedAt}`;
  const hit = tokenCache.get(cacheKey);
  if (hit) return hit;
  const token = await signCeilingTokenWith(record, version, key, kid, IDP_CONFIG.issuer);
  if (tokenCache.size > 20) tokenCache.clear();
  tokenCache.set(cacheKey, token);
  return token;
}
