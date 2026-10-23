/**
 * Durable retry of sign-out notifications (ops/notificationOutbox.ts). The schedule is pure; queueing, retrying, giving up and the
 * counters run against the dev `idp` database with scratch rows (removed in afterAll).
 */
import { pool } from '../src/db/pool.js';
import {
  enqueueNotification, GIVE_UP_AFTER_MS, outboxStats, processDueNotifications, purgeFinishedNotifications, retryDelayMs, shouldAbandon,
  type NotificationHandlers,
} from '../src/ops/notificationOutbox.js';

const TAG = 'jest-outbox';
const acct = (n: string) => `${TAG}-${n}`;

const ok: NotificationHandlers = { 'dms-logout': async () => true, 'gms-revoke': async () => undefined, 'app-logout': async () => true };
const refused: NotificationHandlers = { 'dms-logout': async () => false, 'gms-revoke': async () => { throw Object.assign(new Error('connect ECONNREFUSED 10.1.1.1:7200'), { code: 'ECONNREFUSED' }); }, 'app-logout': async () => false };

const row = async (a: string) => (await pool.query('SELECT * FROM idp_pending_notifications WHERE account_id = $1 ORDER BY id DESC LIMIT 1', [a])).rows[0];
const makeDue = (a: string) => pool.query(`UPDATE idp_pending_notifications SET next_attempt_at = NOW() - INTERVAL '1 second' WHERE account_id = $1 AND status = 'pending'`, [a]);

beforeEach(async () => {
  await pool.query('DELETE FROM idp_pending_notifications WHERE account_id LIKE $1', [`${TAG}-%`]);
});
afterAll(async () => {
  await pool.query('DELETE FROM idp_pending_notifications WHERE account_id LIKE $1', [`${TAG}-%`]);
  await pool.end();
});

describe('the retry schedule', () => {
  it('grows from a minute and settles at four hours', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 8].map(retryDelayMs)).toEqual([60_000, 120_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 14_400_000]);
    expect(retryDelayMs(9)).toBe(14_400_000);
    expect(retryDelayMs(500)).toBe(14_400_000);
    expect(retryDelayMs(0)).toBe(60_000);
  });
  it('gives up after 48 hours', () => {
    const now = Date.now();
    expect(shouldAbandon(now - GIVE_UP_AFTER_MS + 60_000, now)).toBe(false);
    expect(shouldAbandon(now - GIVE_UP_AFTER_MS, now)).toBe(true);
    expect(shouldAbandon(new Date(now - 3 * GIVE_UP_AFTER_MS), now)).toBe(true);
  });
});

describe('queueing', () => {
  it('writes a pending row due in a minute', async () => {
    await enqueueNotification('dms-logout', acct('a'));
    const r = await row(acct('a'));
    expect(r).toMatchObject({ kind: 'dms-logout', status: 'pending', attempts: 0 });
    expect(new Date(r.next_attempt_at).getTime()).toBeGreaterThan(Date.now() + 30_000);
  });

  it('signing the same person out repeatedly while the other system is down queues ONE retry', async () => {
    for (let i = 0; i < 5; i += 1) await enqueueNotification('dms-logout', acct('b'));
    const { rows } = await pool.query(`SELECT 1 FROM idp_pending_notifications WHERE account_id = $1 AND status = 'pending'`, [acct('b')]);
    expect(rows).toHaveLength(1);
  });

  it('a DMS retry and a GMS retry for the same person are separate', async () => {
    await enqueueNotification('dms-logout', acct('c'));
    await enqueueNotification('gms-revoke', acct('c'), 'Person@Example.com');
    const { rows } = await pool.query(`SELECT kind, email FROM idp_pending_notifications WHERE account_id = $1 ORDER BY kind`, [acct('c')]);
    expect(rows).toEqual([{ kind: 'dms-logout', email: '' }, { kind: 'gms-revoke', email: 'person@example.com' }]);
  });
});

describe('retrying', () => {
  it('does nothing until a notification is due', async () => {
    await enqueueNotification('dms-logout', acct('d'));
    const seen: string[] = [];
    await processDueNotifications({ ...ok, 'dms-logout': async (a) => { seen.push(a); return true; } });
    expect(seen).not.toContain(acct('d'));
    expect((await row(acct('d'))).status).toBe('pending');
  });

  it('a due notification that goes through is marked done', async () => {
    await enqueueNotification('dms-logout', acct('e'));
    await makeDue(acct('e'));
    const out = await processDueNotifications(ok);
    expect(out.done).toBeGreaterThanOrEqual(1);
    expect(await row(acct('e'))).toMatchObject({ status: 'done', attempts: 1, last_error: '' });
  });

  it('a failure is rescheduled with a longer delay, and records the failure class only', async () => {
    await enqueueNotification('gms-revoke', acct('f'), 'f@example.com');
    await makeDue(acct('f'));
    await processDueNotifications(refused);
    const r = await row(acct('f'));
    expect(r).toMatchObject({ status: 'pending', attempts: 1 });
    expect(r.last_error).toBe('Error (ECONNREFUSED)');
    expect(r.last_error).not.toMatch(/10\.1\.1\.1/);
    expect(new Date(r.next_attempt_at).getTime()).toBeGreaterThan(Date.now() + 90_000);
  });

  it('a DMS that answers "no" counts as a failure to retry', async () => {
    await enqueueNotification('dms-logout', acct('g'));
    await makeDue(acct('g'));
    await processDueNotifications(refused);
    expect(await row(acct('g'))).toMatchObject({ status: 'pending', attempts: 1, last_error: 'not acknowledged' });
  });

  it('gives up after 48 hours and says so', async () => {
    await enqueueNotification('dms-logout', acct('h'));
    await pool.query(`UPDATE idp_pending_notifications SET created_at = NOW() - INTERVAL '49 hours', next_attempt_at = NOW() - INTERVAL '1 second' WHERE account_id = $1`, [acct('h')]);
    const out = await processDueNotifications(refused);
    expect(out.abandoned).toBeGreaterThanOrEqual(1);
    expect((await row(acct('h'))).status).toBe('abandoned');
    expect((await outboxStats()).abandonedLast7Days).toBeGreaterThanOrEqual(1);
  });

  it('after an abandoned one, a fresh notification for the same person can be queued again', async () => {
    await enqueueNotification('dms-logout', acct('i'));
    await pool.query(`UPDATE idp_pending_notifications SET status = 'abandoned', finished_at = NOW() WHERE account_id = $1`, [acct('i')]);
    await enqueueNotification('dms-logout', acct('i'));
    const { rows } = await pool.query(`SELECT status FROM idp_pending_notifications WHERE account_id = $1 ORDER BY id`, [acct('i')]);
    expect(rows.map((r) => r.status)).toEqual(['abandoned', 'pending']);
  });
});

describe('visibility and housekeeping', () => {
  it('counts what is waiting and how long the oldest has waited', async () => {
    await enqueueNotification('dms-logout', acct('j'));
    await pool.query(`UPDATE idp_pending_notifications SET created_at = NOW() - INTERVAL '20 minutes' WHERE account_id = $1`, [acct('j')]);
    const stats = await outboxStats();
    expect(stats.pending).toBeGreaterThanOrEqual(1);
    expect(stats.oldestPendingSeconds).toBeGreaterThanOrEqual(19 * 60);
  });

  it('purges finished rows after a day and abandoned ones after a month, never pending ones', async () => {
    for (const n of ['k1', 'k2', 'k3', 'k4']) await enqueueNotification('dms-logout', acct(n));
    await pool.query(`UPDATE idp_pending_notifications SET status = 'done', finished_at = NOW() - INTERVAL '2 days' WHERE account_id = $1`, [acct('k1')]);
    await pool.query(`UPDATE idp_pending_notifications SET status = 'abandoned', finished_at = NOW() - INTERVAL '31 days' WHERE account_id = $1`, [acct('k2')]);
    await pool.query(`UPDATE idp_pending_notifications SET status = 'abandoned', finished_at = NOW() - INTERVAL '2 days' WHERE account_id = $1`, [acct('k3')]);
    await purgeFinishedNotifications();
    const { rows } = await pool.query(`SELECT account_id FROM idp_pending_notifications WHERE account_id LIKE $1 ORDER BY account_id`, [`${TAG}-k%`]);
    expect(rows.map((r) => r.account_id)).toEqual([acct('k3'), acct('k4')]);
  });
});

describe('notifications to a registered application (app-logout:<client id>)', () => {
  it('is queued per application, retried with the client id and the account, and marked done when acknowledged', async () => {
    await enqueueNotification('app-logout:shop', acct('app'));
    await enqueueNotification('app-logout:mos', acct('app'));
    expect((await pool.query('SELECT kind FROM idp_pending_notifications WHERE account_id = $1 ORDER BY kind', [acct('app')])).rows.map((r) => r.kind)).toEqual(['app-logout:mos', 'app-logout:shop']);
    await enqueueNotification('app-logout:shop', acct('app')); // the same one again: still a single pending row
    expect((await pool.query("SELECT 1 FROM idp_pending_notifications WHERE account_id = $1 AND kind = 'app-logout:shop'", [acct('app')])).rowCount).toBe(1);
    await makeDue(acct('app'));
    const seen: string[] = [];
    const out = await processDueNotifications({ ...ok, 'app-logout': async (client, account) => { seen.push(`${client}:${account}`); return true; } });
    expect(out.done).toBeGreaterThanOrEqual(2);
    expect(seen.sort()).toEqual([`mos:${acct('app')}`, `shop:${acct('app')}`]);
  });

  it('is rescheduled when the application still does not answer', async () => {
    await enqueueNotification('app-logout:shop', acct('retry'));
    await makeDue(acct('retry'));
    await processDueNotifications(refused);
    expect(await row(acct('retry'))).toMatchObject({ status: 'pending', attempts: 1 });
  });
});
