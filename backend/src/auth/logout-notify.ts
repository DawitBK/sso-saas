/**
 * Logout propagation to DMS — an OIDC backchannel-logout-style notification.
 * The IdP signs a standard logout token (RS256, its own JWKS key) and POSTs it
 * to DMS; DMS verifies it against the published JWKS and revokes that user's
 * sessions (see DMS /auth/backchannel-logout). Best-effort: a DMS outage never
 * blocks sign-out — the token is also useless to anyone else (2-minute expiry,
 * aud-bound, verifiable only against our JWKS).
 */

import { SignJWT, importJWK } from 'jose';
import crypto from 'node:crypto';
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';
import type { PrivateJwk } from '../jwks.js';

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

export async function notifyDmsLogout(accountId: string): Promise<boolean> {
  const uri = IDP_CONFIG.dms.backchannelLogoutUri;
  if (!uri) return false;
  try {
    const { rows } = await pool.query<{ jwk: PrivateJwk }>(
      'SELECT jwk FROM idp_signing_keys WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1',
    );
    if (!rows[0]) return false;
    const jwk = rows[0].jwk;
    const key = await importJWK(jwk as never, 'RS256');

    const logoutToken = await new SignJWT({
      events: { [LOGOUT_EVENT]: {} },
      sub: accountId,
    })
      .setProtectedHeader({ alg: 'RS256', kid: jwk.kid, typ: 'logout+jwt' })
      .setIssuer(IDP_CONFIG.issuer)
      .setAudience('edams')
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .setExpirationTime('2m')
      .sign(key);

    const res = await fetch(uri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ logout_token: logoutToken }).toString(),
    });
    return res.ok;
  } catch {
    return false;
  }
}
