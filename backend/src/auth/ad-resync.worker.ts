/**
 * Periodic AD group re-sync for users who currently have a live session.
 *
 * Platform audit finding 4.7: AD group membership was only ever checked at
 * login (upsertAdUser, local-users.ts) — a user removed from an
 * app-entitled or elevated-role group mid-session kept that access until
 * their session naturally expired (14 days) or they logged in again, since
 * nothing rechecked AD in between. This sweep closes that gap by re-running
 * the same shrink-detection-and-revoke logic on a timer, scoped to only the
 * (typically small) set of AD-sourced users who actually have a session
 * open right now — not every AD user, to keep LDAP load proportional to
 * actual usage rather than directory size.
 */

import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';
import { isAdEnabled, lookupAdGroupsByEmail } from './ldap.service.js';
import { syncAdGroupMembership } from './local-users.js';

export async function resyncActiveAdSessions(): Promise<void> {
  if (!isAdEnabled()) return;

  const { rows } = await pool.query<{ id: string; email: string }>(
    `SELECT DISTINCT u.id, u.email
     FROM idp_users u
     JOIN oidc_artifacts a
       ON a.kind = 'Session'
      AND a.payload->>'accountId' = u.id::text
      AND (a.expires_at IS NULL OR a.expires_at > NOW())
     WHERE u.source = 'ad' AND u.is_active = TRUE`,
  );

  if (rows.length === 0) return;

  logger.info({ count: rows.length }, '[idp:ad-resync] checking AD group membership for active sessions');

  for (const { id, email } of rows) {
    try {
      const groups = await lookupAdGroupsByEmail(email);
      if (groups === null) {
        // User not found in AD anymore (deleted/renamed) — leave their group
        // rows as-is rather than guessing; an explicit admin disable/removal
        // is the correct way to cut off someone AD no longer knows about.
        logger.warn({ userId: id, email }, '[idp:ad-resync] user not found in AD, skipping');
        continue;
      }
      const shrank = await syncAdGroupMembership(id, email, groups);
      if (shrank) {
        logger.info({ userId: id, email }, '[idp:ad-resync] AD group membership narrowed, sessions revoked');
      }
    } catch (err) {
      // One user's lookup failing (transient LDAP issue, odd directory data)
      // must not stop the rest of the sweep.
      logger.error({ err, userId: id, email }, '[idp:ad-resync] failed to re-check AD groups for this user');
    }
  }
}
