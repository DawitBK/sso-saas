/**
 * "I forgot my password", with no mail server (migration 022).
 *
 * A person asks on the sign-in page; the request appears for administrators under Admin > Users, who reset the password the way they always
 * could and give the person the temporary one in person or by phone. Nothing is emailed and nothing is revealed to the asker.
 *
 * What a request protects against, in the order it matters:
 *  - Enumeration: the public answer is identical whether or not the address has an account.
 *  - Flooding: one OPEN request per person (asking again refreshes it); the route is rate-limited per address (api/v1/index.ts).
 *  - Reaching a person who cannot be reset here: Active Directory accounts (their password lives in the directory), disabled accounts and
 *    the platform administrator never get a request.
 *  - Content: the note is plain text, capped, and shown escaped; the sign-in address is recorded only as the administrator's context.
 */
import { pool } from '../db/pool.js';
import { getBool } from '../settings/store.js';

export const MAX_NOTE_LENGTH = 200;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/;

/** Returns true when a request was recorded. The caller must answer the same way either way. */
export async function createResetRequest(emailRaw: unknown, noteRaw: unknown, ip: string): Promise<boolean> {
  if (!getBool('password.allowResetRequests')) return false;
  const email = typeof emailRaw === 'string' ? emailRaw.trim().toLowerCase() : '';
  if (!EMAIL.test(email) || email.length > 254) return false;
  // eslint-disable-next-line no-control-regex
  const note = (typeof noteRaw === 'string' ? noteRaw : '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, MAX_NOTE_LENGTH);

  const { rows } = await pool.query<{ id: string }>(
    `SELECT id FROM idp_users WHERE lower(email) = $1 AND source = 'local' AND is_active AND NOT is_platform_admin AND password_hash IS NOT NULL`,
    [email],
  );
  const user = rows[0];
  if (!user) return false;
  await pool.query(
    `INSERT INTO idp_password_reset_requests (user_id, email, note, requested_ip)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (user_id) WHERE status = 'open'
     DO UPDATE SET requested_at = NOW(), note = EXCLUDED.note, requested_ip = EXCLUDED.requested_ip`,
    [user.id, email, note, ip.slice(0, 64)],
  );
  return true;
}

export interface ResetRequestRow {
  id: string;
  userId: string;
  email: string;
  name: string;
  note: string;
  requestedAt: string;
}

/** The open requests, oldest first (the person who has waited longest is served first). */
export async function listOpenResetRequests(): Promise<ResetRequestRow[]> {
  const { rows } = await pool.query<{ id: string; user_id: string; email: string; given_name: string | null; family_name: string | null; note: string; requested_at: Date }>(
    `SELECT r.id, r.user_id, u.email, u.given_name, u.family_name, r.note, r.requested_at
       FROM idp_password_reset_requests r
       JOIN idp_users u ON u.id = r.user_id
      WHERE r.status = 'open' AND NOT u.is_platform_admin
      ORDER BY r.requested_at ASC
      LIMIT 200`,
  );
  return rows.map((r) => ({
    id: String(r.id),
    userId: r.user_id,
    email: r.email,
    name: [r.given_name, r.family_name].filter(Boolean).join(' '),
    note: r.note,
    requestedAt: new Date(r.requested_at).toISOString(),
  }));
}

/** An administrator reset this person's password: their open request is done. */
export async function closeRequestsForUser(userId: string, by: string): Promise<void> {
  await pool.query(
    `UPDATE idp_password_reset_requests SET status = 'done', handled_by = $2, handled_at = NOW() WHERE user_id = $1 AND status = 'open'`,
    [userId, by],
  );
}

/** Dismiss one open request (a duplicate, or someone who remembered). Returns the person's email, or null if there was no such open request. */
export async function dismissResetRequest(id: string, by: string): Promise<string | null> {
  if (!/^\d{1,18}$/.test(id)) return null;
  const { rows } = await pool.query<{ email: string }>(
    `UPDATE idp_password_reset_requests SET status = 'dismissed', handled_by = $2, handled_at = NOW() WHERE id = $1 AND status = 'open' RETURNING email`,
    [id, by],
  );
  return rows[0]?.email ?? null;
}

/** Housekeeping for the purge job: handled requests are kept 90 days, and a request nobody touched for 30 days is stale. */
export async function purgeResetRequests(): Promise<void> {
  await pool.query(`DELETE FROM idp_password_reset_requests WHERE status <> 'open' AND handled_at < NOW() - INTERVAL '90 days'`);
  await pool.query(`DELETE FROM idp_password_reset_requests WHERE status = 'open' AND requested_at < NOW() - INTERVAL '30 days'`);
}
