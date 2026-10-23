/**
 * Session revocation — the "disable everywhere" backbone. Deletes every live
 * credential the IdP controls for a user:
 *   - oidc-provider artifacts (SSO Session, tokens, grants, codes) by accountId
 *   - portal sessions (idp_web_sessions kind 'portal')
 *   - gateway sessions (idp_web_sessions kind 'gateway', matched by email)
 *   - GMS auth_sessions minted by the bridge (via revokeGmsSessionsByEmail)
 *
 * DMS's own access and refresh tokens are stateless and cannot be deleted from here; they are
 * ended by the signed backchannel-logout notification (notifyDmsLogout) that sets a per-user
 * revocation cutoff in DMS - best-effort, retried, and reported as `dmsNotified` below. If it
 * is false the DMS session survives until it expires (DMS_ACCESS/REFRESH token lifetime).
 * New SSO logins are refused immediately because findAccount rejects inactive users.
 */

import { pool } from '../db/pool.js';
import { revokeGmsSessionsByEmail } from '../bridge/gms.js';
import { notifyAppLogouts, notifyDmsLogout } from './logout-notify.js';
import { logger } from '../logging/logger.js';
import { enqueueNotification } from '../ops/notificationOutbox.js';

export interface RevocationResult {
  oidcArtifacts: number;
  portalSessions: number;
  gatewaySessions: number;
  /** Parked, half-finished logins (MFA step / forced password change / pending
   *  OIDC flows) — see the note in revokeAllSessions. */
  pendingLogins: number;
  /**
   * Count of GMS sessions revoked, or the literal 'failed' when GMS could not
   * be reached. Previously a bare number, so a GMS-side failure was reported as
   * `0` — indistinguishable from "there were none to revoke", which made a
   * half-completed "disable this user" look like a clean success.
   */
  gmsSessions: number | 'failed';
  dmsNotified: boolean;
  /** Client ids of the other registered applications (MOS, product apps) that did not confirm; empty or absent when all did or none is registered. */
  appsFailed?: string[];
}

export async function revokeAllSessions(accountId: string, email: string): Promise<RevocationResult> {
  const [oidc, portal, gateway, pending] = await Promise.all([
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
    /**
     * Half-finished logins for this account. Without this, a user who was
     * mid-flow when an admin disabled them kept a live parked session: the
     * 'mfa' row holds an already-password-verified accountId for 10 minutes,
     * and 'pwchange' likewise. Killing every other credential while leaving a
     * verified-but-unfinished login alive is exactly the gap "disable
     * everywhere" is supposed to close. ('pending_portal'/'pending_gms' are
     * keyed by OIDC state rather than account, so they are swept by TTL and
     * cannot be targeted here — they carry no account identity to match on.)
     */
    pool.query(
      `DELETE FROM idp_web_sessions
       WHERE kind IN ('mfa', 'pwchange', 'totp_enroll') AND payload->>'accountId' = $1`,
      [accountId],
    ),
  ]);

  let gmsSessions: number | 'failed' = 0;
  try {
    gmsSessions = await revokeGmsSessionsByEmail(email);
  } catch (err) {
    // GMS unreachable. Everything IdP-side is already dead, so this stays
    // best-effort rather than throwing — but it must be visible, not swallowed:
    // the caller renders this result to an admin who just clicked "sign out
    // everywhere", and GMS is still holding a live session for the user.
    gmsSessions = 'failed';
    await enqueueNotification('gms-revoke', accountId, email);
    logger.error(
      { err, email },
      '[idp:revoke:ALERT] GMS session revoke FAILED — IdP-side credentials are revoked but GMS may still hold a live session for this user',
    );
  }

  // DMS holds its own tokens — tell it to revoke this user's sessions too.
  // The other registered applications (MOS, the product apps) hold their own sessions too.
  const [dmsNotified, appsFailed] = await Promise.all([notifyDmsLogout(accountId), notifyAppLogouts(accountId)]);

  return {
    oidcArtifacts: oidc.rowCount ?? 0,
    portalSessions: portal.rowCount ?? 0,
    gatewaySessions: gateway.rowCount ?? 0,
    pendingLogins: pending.rowCount ?? 0,
    gmsSessions,
    dmsNotified,
    appsFailed,
  };
}

/**
 * A sentence for the administrator when a disable did not reach every system, or null when it
 * did. SSO, portal and gateway sessions are deleted in the same call, so only GMS (its own
 * session rows, reached over HTTP) and DMS (stateless tokens, told by a signed notification
 * that is retried a few times) can still be live.
 */
export function disableWarning(r: RevocationResult | null): string | null {
  if (!r) return null;
  const parts: string[] = [];
  if (r.gmsSessions === 'failed') {
    parts.push('GMS could not be reached, so a GMS session may still be live');
  }
  if (!r.dmsNotified) {
    parts.push(
      "DMS did not confirm it ended this person's sessions, so a DMS session may stay live until its token expires"
    );
  }
  if (r.appsFailed && r.appsFailed.length > 0) {
    parts.push(`${r.appsFailed.join(', ')} did not confirm it ended this person's sessions, so a session there may stay live until its token expires`);
  }
  return parts.length
    ? `Account disabled and no new sign-ins are possible, but ${parts.join('; and ')}. SSO keeps trying in the background for 48 hours (see System health); sign the person out in that system by hand if it cannot wait.`
    : null;
}
