/**
 * Logout propagation to the systems that keep their own sessions — an OIDC backchannel-logout-style notification.
 * The IdP signs a standard logout token (RS256, its own JWKS key) and POSTs it to the system; the system verifies it against the published JWKS and
 * revokes that user's sessions (DMS: /auth/backchannel-logout; every application registered through PRODUCT_CLIENTS_JSON or MOS_BACKCHANNEL_LOGOUT_URI
 * exposes the same kind of receiver). Best-effort: an outage never blocks sign-out — the token is also useless to anyone else (2-minute expiry,
 * aud-bound, verifiable only against our JWKS).
 *
 * DMS is addressed with audience `edams` (its client id); every other application with its own client id, so a token minted for one system is
 * refused by every other.
 */

import { SignJWT, importJWK } from 'jose';
import crypto from 'node:crypto';
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';
import type { PrivateJwk } from '../jwks.js';
import { logger } from '../logging/logger.js';
import { enqueueNotification, type NotificationKind } from '../ops/notificationOutbox.js';

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

/** Attempts, per-attempt timeout and backoff for the notification (shared by every target). Exported only so tests can shrink them. */
export const DMS_LOGOUT_NOTIFY = { attempts: 3, timeoutMs: 4000, backoffMs: 300, downMemoryMs: 30_000 };

/** When the last notification to each target exhausted its retries. While a target is known to be down, later
 *  accounts in the same burst (a group-wide revoke loops over every member) make ONE
 *  attempt each instead of paying the full retry budget per member. */
const lastExhaustedAt = new Map<string, number>();
export function resetDmsLogoutNotifyState(): void {
  lastExhaustedAt.clear();
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

interface LogoutTarget {
  /** Short name used in logs and as the memory key. */
  label: string;
  /** The `aud` of the token: the target's OIDC client id. */
  audience: string;
  uri: string;
  /** The outbox kind a failed notification is queued under. */
  queueKind: NotificationKind;
}

/**
 * Tell one system to end this account's sessions. Returns whether it acknowledged.
 *
 * This is the ONLY channel that carries "this person was disabled / lost a role /
 * was signed out" to systems whose own tokens are stateless and which keep no copy of
 * SSO's disabled flag. A single failed attempt used to be final (and the fetch had
 * no timeout, so a hung system stalled the admin's "disable" click): the account was
 * dark in SSO while its session stayed live until refresh-token expiry. So it
 * now retries transport failures, 429 and 5xx a few times with a short backoff,
 * bounds every attempt, and logs an ALERT when the system still could not be told - the
 * caller records the failure in the audit trail, which is the signal an
 * administrator uses to force-logout the user there by hand.
 * A 4xx other than 429 is not retried: the system understood and refused the token.
 */
async function notifyTarget(target: LogoutTarget, accountId: string, queueOnFailure: boolean): Promise<boolean> {
  if (!target.uri) return false;
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
      .setAudience(target.audience)
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .setExpirationTime('2m')
      .sign(key);
  } catch (err) {
    logger.error({ err, accountId, target: target.label }, `[idp:logout-notify:ALERT] could not build the ${target.label} logout token - ${target.label} was NOT told to end the sessions of this account`);
    if (queueOnFailure) await enqueueNotification(target.queueKind, accountId);
    return false;
  }

  const { timeoutMs, backoffMs } = DMS_LOGOUT_NOTIFY;
  const attempts = Date.now() - (lastExhaustedAt.get(target.label) ?? 0) < DMS_LOGOUT_NOTIFY.downMemoryMs ? 1 : DMS_LOGOUT_NOTIFY.attempts;
  let lastFailure = 'unknown';
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      const res = await fetch(target.uri, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ logout_token: logoutToken }).toString(),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) {
        lastExhaustedAt.delete(target.label);
        return true;
      }
      lastFailure = `HTTP ${res.status}`;
      if (res.status < 500 && res.status !== 429) break; // it answered and refused: retrying cannot help
    } catch (err) {
      lastFailure = (err as Error).message;
    }
    if (attempt < attempts) await sleep(backoffMs * attempt);
  }
  lastExhaustedAt.set(target.label, Date.now());
  logger.error(
    { accountId, uri: target.uri, lastFailure, target: target.label },
    `[idp:logout-notify:ALERT] ${target.label} did not acknowledge the logout notification - it is queued and retried for 48 hours; force-logout the user there if that cannot wait`,
  );
  // Written down for the background retry (ops/notificationOutbox.ts), so an outage at the wrong moment does not leave a disabled
  // person signed in there until their token expires.
  if (queueOnFailure) await enqueueNotification(target.queueKind, accountId);
  return false;
}

/** Tell DMS to end this account's sessions. Returns whether DMS acknowledged. */
export async function notifyDmsLogout(accountId: string, opts: { queueOnFailure?: boolean } = {}): Promise<boolean> {
  return notifyTarget(
    { label: 'DMS', audience: 'edams', uri: IDP_CONFIG.dms.backchannelLogoutUri, queueKind: 'dms-logout' },
    accountId,
    opts.queueOnFailure !== false,
  );
}

/** The kind a failed notification to this application is queued under; the retry job parses the client id back out of it. */
export const appLogoutKind = (clientId: string): NotificationKind => `app-logout:${clientId}`;
export const clientIdOfAppLogoutKind = (kind: string): string | null => (kind.startsWith('app-logout:') ? kind.slice('app-logout:'.length) : null);

/** Tell ONE registered application (MOS or a product app) to end this account's sessions. False when it did not acknowledge or is not registered. */
export async function notifyAppLogout(clientId: string, accountId: string, opts: { queueOnFailure?: boolean } = {}): Promise<boolean> {
  const target = IDP_CONFIG.appLogoutTargets.find((t) => t.client_id === clientId);
  if (!target) return false;
  return notifyTarget({ label: clientId, audience: clientId, uri: target.uri, queueKind: appLogoutKind(clientId) }, accountId, opts.queueOnFailure !== false);
}

/** Tell every registered application to end this account's sessions, side by side. Returns the client ids that did NOT acknowledge (empty = all did, or none are registered). */
export async function notifyAppLogouts(accountId: string): Promise<string[]> {
  const results = await Promise.all(IDP_CONFIG.appLogoutTargets.map(async (t) => ((await notifyAppLogout(t.client_id, accountId)) ? null : t.client_id)));
  return results.filter((id): id is string => id !== null);
}
