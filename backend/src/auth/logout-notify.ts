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
import { logger } from '../logging/logger.js';
import { enqueueNotification } from '../ops/notificationOutbox.js';

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** Attempts, per-attempt timeout and backoff for the DMS notification. Exported only so tests can shrink them. */
export const DMS_LOGOUT_NOTIFY = { attempts: 3, timeoutMs: 4000, backoffMs: 300, downMemoryMs: 30_000 };

/** When the last notification exhausted its retries. While DMS is known to be down, later
 *  accounts in the same burst (a group-wide revoke loops over every member) make ONE
 *  attempt each instead of paying the full retry budget per member. */
let lastExhaustedAt = 0;
export function resetDmsLogoutNotifyState(): void {
  lastExhaustedAt = 0;
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Tell DMS to end this account's sessions. Returns whether DMS acknowledged.
 *
 * This is the ONLY channel that carries "this person was disabled / lost a role /
 * was signed out" to DMS, whose own tokens are stateless and which keeps no copy of
 * SSO's disabled flag. A single failed attempt used to be final (and the fetch had
 * no timeout, so a hung DMS stalled the admin's "disable" click): the account was
 * dark in SSO while its DMS session stayed live until refresh-token expiry. So it
 * now retries transport failures, 429 and 5xx a few times with a short backoff,
 * bounds every attempt, and logs an ALERT when DMS still could not be told - the
 * caller records `dmsNotified:false` in the audit trail, which is the signal an
 * administrator uses to force-logout the user from DMS by hand.
 * A 4xx other than 429 is not retried: DMS understood and refused the token.
 */
export async function notifyDmsLogout(accountId: string, opts: { queueOnFailure?: boolean } = {}): Promise<boolean> {
  const queueOnFailure = opts.queueOnFailure !== false;
  const uri = IDP_CONFIG.dms.backchannelLogoutUri;
  if (!uri) return false;
  let logoutToken: string;
  try {
    const { rows } = await pool.query<{ jwk: PrivateJwk }>(
      'SELECT jwk FROM idp_signing_keys WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1',
    );
    if (!rows[0]) return false;
    const jwk = rows[0].jwk;
    const key = await importJWK(jwk as never, 'RS256');

    logoutToken = await new SignJWT({
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
  } catch (err) {
    logger.error({ err, accountId }, '[idp:logout-notify:ALERT] could not build the DMS logout token - DMS was NOT told to end the sessions of this account');
    if (queueOnFailure) await enqueueNotification('dms-logout', accountId);
    return false;
  }

  const { timeoutMs, backoffMs } = DMS_LOGOUT_NOTIFY;
  const attempts = Date.now() - lastExhaustedAt < DMS_LOGOUT_NOTIFY.downMemoryMs ? 1 : DMS_LOGOUT_NOTIFY.attempts;
  let lastFailure = 'unknown';
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetch(uri, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ logout_token: logoutToken }).toString(),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) {
        lastExhaustedAt = 0;
        return true;
      }
      lastFailure = `HTTP ${res.status}`;
      if (res.status < 500 && res.status !== 429) break; // DMS answered and refused: retrying cannot help
    } catch (err) {
      lastFailure = (err as Error).message;
    }
    if (attempt < attempts) await sleep(backoffMs * attempt);
  }
  lastExhaustedAt = Date.now();
  logger.error(
    { accountId, uri, lastFailure },
    '[idp:logout-notify:ALERT] DMS did not acknowledge the logout notification - it is queued and retried for 48 hours; force-logout the user in DMS if that cannot wait',
  );
  // Written down for the background retry (ops/notificationOutbox.ts), so a DMS outage at the wrong moment does not leave a disabled
  // person signed in there until their token expires.
  if (queueOnFailure) await enqueueNotification('dms-logout', accountId);
  return false;
}
