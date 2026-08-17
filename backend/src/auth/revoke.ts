/**
 * Session revocation — the "disable everywhere" backbone. Deletes every live
 * credential the IdP controls for a user:
 *   - oidc-provider artifacts (SSO Session, tokens, grants, codes) by accountId
 *   - portal sessions (idp_web_sessions kind 'portal')
 *   - gateway sessions (idp_web_sessions kind 'gateway', matched by email)
 *   - GMS auth_sessions minted by the bridge (via revokeGmsSessionsByEmail)
 *
 * DMS's own access tokens are stateless (1h) and cannot be revoked from here;
 * new logins are refused immediately because findAccount rejects inactive users.
 */

import { pool } from '../db/pool.js';
import { revokeGmsSessionsByEmail } from '../bridge/gms.js';
import { notifyDmsLogout } from './logout-notify.js';

export interface RevocationResult {
  oidcArtifacts: number;
  portalSessions: number;
  gatewaySessions: number;
  gmsSessions: number;
  dmsNotified: boolean;
}

export async function revokeAllSessions(accountId: string, email: string): Promise<RevocationResult> {
  const [oidc, portal, gateway] = await Promise.all([
    pool.query(
      `DELETE FROM oidc_artifacts
       WHERE kind IN ('Session', 'AccessToken', 'RefreshToken', 'Grant', 'AuthorizationCode', 'DeviceCode', 'Interaction')
         AND payload->>'accountId' = $1`,
      [accountId],
    ),
    pool.query(
      `DELETE FROM idp_web_sessions WHERE kind = 'portal' AND payload->>'accountId' = $1`,
      [accountId],
    ),
    pool.query(
      `DELETE FROM idp_web_sessions WHERE kind = 'gateway' AND payload->>'email' = $1`,
      [email.toLowerCase()],
    ),
  ]);

  let gmsSessions = 0;
  try {
    gmsSessions = await revokeGmsSessionsByEmail(email);
  } catch {
    // GMS unreachable — best-effort; everything IdP-side is already dead.
  }

  // DMS holds its own tokens — tell it to revoke this user's sessions too.
  const dmsNotified = await notifyDmsLogout(accountId);

  return {
    oidcArtifacts: oidc.rowCount ?? 0,
    portalSessions: portal.rowCount ?? 0,
    gatewaySessions: gateway.rowCount ?? 0,
    gmsSessions,
    dmsNotified,
  };
}
