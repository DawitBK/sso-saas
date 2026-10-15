/**
 * Durable retry for the notifications SSO sends to DMS and GMS when someone is signed out or disabled.
 *
 * What goes wrong without it: SSO deletes every credential it holds the moment an administrator disables a person, but DMS (stateless
 * tokens) and GMS (its own session rows) are told over HTTP. Those calls were retried a few times in a row and then forgotten, so a
 * DMS outage at the wrong moment left a disabled person signed in to DMS until their token ran out. Here a failed call is written down
 * and a background job tries again, with a growing delay, for up to 48 hours; the System page shows what is waiting.
 *
 * The retry handlers are PASSED IN by the caller of processDueNotifications (main.ts), not imported: the code that sends the
 * notification imports this module to queue a failure, and importing back would be a cycle.
 */
import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';

export type NotificationKind = 'dms-logout' | 'gms-revoke';

/** Delay before attempt 2, 3, 4 ... then every 4 hours. */
export const RETRY_DELAYS_MS = [60_000, 120_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 14_400_000];
/** After this long without success the notification is abandoned and reported, so the administrator knows to act by hand. */
export const GIVE_UP_AFTER_MS = 48 * 3_600_000;

/** How long to wait after `attempts` failed attempts (1 = the first retry's delay). */
export function retryDelayMs(attempts: number): number {
  const i = Math.max(1, Math.floor(attempts)) - 1;
  return RETRY_DELAYS_MS[Math.min(i, RETRY_DELAYS_MS.length - 1)] as number;
}

/** True once a notification created at `createdAt` has been tried for long enough. */
export function shouldAbandon(createdAt: Date | string | number, now: number = Date.now()): boolean {
  return now - new Date(createdAt).getTime() >= GIVE_UP_AFTER_MS;
}

/** Queue a notification that did not get through. One pending row per (kind, account). Never throws: the caller is already in a failure path. */
export async function enqueueNotification(kind: NotificationKind, accountId: string, email = ''): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO idp_pending_notifications (kind, account_id, email, next_attempt_at)
       VALUES ($1, $2, $3, NOW() + ($4 || ' milliseconds')::interval)
       ON CONFLICT (kind, account_id) WHERE status = 'pending' DO NOTHING`,
      [kind, accountId, email.toLowerCase(), String(retryDelayMs(1))],
    );
  } catch (err) {
    logger.error({ err, kind, accountId }, '[idp:notify-outbox:ALERT] could not queue a failed sign-out notification for retry');
  }
}

export interface NotificationHandlers {
  /** true when DMS acknowledged. */
  'dms-logout': (accountId: string) => Promise<boolean>;
  /** Resolves when GMS sessions for this email were revoked, throws when GMS could not be reached. */
  'gms-revoke': (email: string) => Promise<unknown>;
}

interface Row {
  id: string;
  kind: NotificationKind;
  account_id: string;
  email: string;
  attempts: number;
  created_at: Date;
}

const classOf = (err: unknown): string => {
  const e = err as { name?: string; code?: string };
  return [e?.name ?? 'Error', e?.code ? `(${e.code})` : ''].filter(Boolean).join(' ');
};

/** One pass: retry every due notification once. Returns how many succeeded, were rescheduled and were abandoned. */
export async function processDueNotifications(handlers: NotificationHandlers, batch = 20): Promise<{ done: number; retry: number; abandoned: number }> {
  const out = { done: 0, retry: 0, abandoned: 0 };
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    // SKIP LOCKED: a second process (or an overlapping run) never works the same row.
    const { rows } = await db.query<Row>(
      `SELECT id, kind, account_id, email, attempts, created_at FROM idp_pending_notifications
        WHERE status = 'pending' AND next_attempt_at <= NOW()
        ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED`,
      [batch],
    );
    for (const row of rows) {
      let ok = false;
      let failure = '';
      try {
        ok = row.kind === 'dms-logout' ? await handlers['dms-logout'](row.account_id) : (await handlers['gms-revoke'](row.email), true);
        if (!ok) failure = 'not acknowledged';
      } catch (err) {
        failure = classOf(err);
      }
      if (ok) {
        await db.query(`UPDATE idp_pending_notifications SET status = 'done', finished_at = NOW(), attempts = attempts + 1, last_error = '' WHERE id = $1`, [row.id]);
        out.done += 1;
        logger.info({ kind: row.kind, accountId: row.account_id, attempts: row.attempts + 1 }, '[idp:notify-outbox] a queued sign-out notification went through');
      } else if (shouldAbandon(row.created_at)) {
        await db.query(`UPDATE idp_pending_notifications SET status = 'abandoned', finished_at = NOW(), attempts = attempts + 1, last_error = $2 WHERE id = $1`, [row.id, failure]);
        out.abandoned += 1;
        logger.error({ kind: row.kind, accountId: row.account_id }, '[idp:notify-outbox:ALERT] gave up telling another system someone was signed out after 48 hours; end their session there by hand');
      } else {
        await db.query(
          `UPDATE idp_pending_notifications SET attempts = attempts + 1, last_error = $2, next_attempt_at = NOW() + ($3 || ' milliseconds')::interval WHERE id = $1`,
          [row.id, failure, String(retryDelayMs(row.attempts + 2))],
        );
        out.retry += 1;
      }
    }
    await db.query('COMMIT');
  } catch (err) {
    await db.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    db.release();
  }
  return out;
}

export interface OutboxStats {
  pending: number;
  /** Seconds the oldest pending notification has been waiting, or null. */
  oldestPendingSeconds: number | null;
  /** Notifications given up on in the last 7 days. */
  abandonedLast7Days: number;
}

export async function outboxStats(): Promise<OutboxStats> {
  const { rows } = await pool.query<{ pending: string; oldest: string | null; abandoned: string }>(
    `SELECT COUNT(*) FILTER (WHERE status = 'pending') AS pending,
            EXTRACT(EPOCH FROM (NOW() - MIN(created_at) FILTER (WHERE status = 'pending')))::bigint AS oldest,
            COUNT(*) FILTER (WHERE status = 'abandoned' AND finished_at > NOW() - INTERVAL '7 days') AS abandoned
       FROM idp_pending_notifications`,
  );
  const r = rows[0];
  return { pending: Number(r?.pending ?? 0), oldestPendingSeconds: r?.oldest === null || r?.oldest === undefined ? null : Number(r.oldest), abandonedLast7Days: Number(r?.abandoned ?? 0) };
}

/** Housekeeping for the purge job: finished rows are only kept briefly. */
export async function purgeFinishedNotifications(): Promise<void> {
  await pool.query(`DELETE FROM idp_pending_notifications WHERE status = 'done' AND finished_at < NOW() - INTERVAL '1 day'`);
  await pool.query(`DELETE FROM idp_pending_notifications WHERE status = 'abandoned' AND finished_at < NOW() - INTERVAL '30 days'`);
}
