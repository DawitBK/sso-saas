/**
 * Local user store (fallback identity source). AD-primary means most users are
 * NOT here; this covers service accounts / non-AD users. Group memberships are
 * expressed as AD-style DNs so the issued token's `ad_groups` claim looks the
 * same regardless of source.
 */

import crypto from 'node:crypto';
import { pool } from '../db/pool.js';
import { hashPassword, verifyPassword } from './password.js';
import { decryptTotpSecret, encryptTotpSecret } from './totp.js';
import { revokeAllSessions } from './revoke.js';
import { logger } from '../logging/logger.js';

/**
 * Cached dummy scrypt hash used to keep `authenticateLocal`'s response time
 * roughly constant across "account doesn't exist" / "inactive" / "locked" /
 * "wrong password" — without this, those first three return almost instantly
 * (a DB lookup only) while a genuine wrong-password attempt pays a real
 * scrypt derivation, making response time itself an oracle for account
 * existence/state even though the error message is already generic.
 */
let dummyHashPromise: Promise<string> | null = null;
function getDummyHash(): Promise<string> {
  if (!dummyHashPromise) dummyHashPromise = hashPassword(crypto.randomBytes(32).toString('hex'));
  return dummyHashPromise;
}

export interface LocalUser {
  id: string;
  email: string;
  emailVerified: boolean;
  givenName: string;
  familyName: string;
  isActive: boolean;
  mustChangePassword: boolean;
  groups: string[];
}

const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_MINUTES = 15;

interface UserRow {
  id: string;
  email: string;
  email_verified: boolean;
  given_name: string;
  family_name: string;
  password_hash: string | null;
  is_active: boolean;
  must_change_password: boolean;
  failed_logins: number;
  locked_until: Date | null;
}

async function loadGroups(userId: string): Promise<string[]> {
  const { rows } = await pool.query<{ group_dn: string }>(
    `SELECT group_dn FROM idp_user_groups WHERE user_id = $1`,
    [userId],
  );
  return rows.map((r) => r.group_dn);
}

function toLocalUser(row: UserRow, groups: string[]): LocalUser {
  return {
    id: row.id,
    email: row.email,
    emailVerified: row.email_verified,
    givenName: row.given_name,
    familyName: row.family_name,
    isActive: row.is_active,
    mustChangePassword: row.must_change_password,
    groups,
  };
}

/**
 * Whether this account is allowed to change its own password from the portal.
 * AD-sourced accounts manage their password in AD (upsertAdUser never sets
 * password_hash for them) — letting an AD account also set a local password
 * here would create a second, IdP-only credential that keeps working even
 * after the real AD password is rotated or the AD account is disabled,
 * silently undermining AD's own policy/lockout. Local accounts with no
 * password_hash at all shouldn't hit this either (defensive; admin-created
 * local users always get one).
 */
export async function canSelfChangePassword(userId: string): Promise<boolean> {
  const { rows } = await pool.query<{ source: string; password_hash: string | null }>(
    'SELECT source, password_hash FROM idp_users WHERE id = $1',
    [userId],
  );
  const row = rows[0];
  return Boolean(row && row.source === 'local' && row.password_hash);
}

/** Verify the current password for a self-service change (distinct from
 *  authenticateLocal — no lockout bookkeeping here, since the caller already
 *  holds a valid session; a wrong "current password" just rejects the form). */
export async function verifyCurrentPassword(userId: string, password: string): Promise<boolean> {
  const { rows } = await pool.query<{ password_hash: string | null }>(
    'SELECT password_hash FROM idp_users WHERE id = $1',
    [userId],
  );
  return verifyPassword(password, rows[0]?.password_hash ?? null);
}

/** Set a new password and clear the forced-change flag (used by the login-time
 *  change screen after an admin reset). */
export async function completePasswordChange(userId: string, passwordHash: string): Promise<void> {
  await pool.query(
    `UPDATE idp_users
     SET password_hash = $2, must_change_password = FALSE, failed_logins = 0, locked_until = NULL, updated_at = NOW()
     WHERE id = $1`,
    [userId, passwordHash],
  );
}

// ── TOTP / MFA state ─────────────────────────────────────────────────────────

export async function getTotpState(userId: string): Promise<{ enabled: boolean; secret: string | null }> {
  const { rows } = await pool.query<{ totp_enabled: boolean; totp_secret: string | null }>(
    'SELECT totp_enabled, totp_secret FROM idp_users WHERE id = $1',
    [userId],
  );
  return {
    enabled: rows[0]?.totp_enabled ?? false,
    secret: rows[0]?.totp_secret ? decryptTotpSecret(rows[0].totp_secret) : null,
  };
}

export async function enableTotp(userId: string, secret: string): Promise<void> {
  await pool.query(
    'UPDATE idp_users SET totp_secret = $2, totp_enabled = TRUE, updated_at = NOW() WHERE id = $1',
    [userId, encryptTotpSecret(secret)],
  );
}

export async function disableTotp(userId: string): Promise<void> {
  await pool.query(
    'UPDATE idp_users SET totp_secret = NULL, totp_enabled = FALSE, mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() WHERE id = $1',
    [userId],
  );
}

// ── MFA brute-force lockout (mirrors the password lockout above) ────────────

const MFA_LOCKOUT_THRESHOLD = 5;
const MFA_LOCKOUT_MINUTES = 15;

export async function checkMfaLockout(userId: string): Promise<{ locked: boolean }> {
  const { rows } = await pool.query<{ mfa_locked_until: Date | null }>(
    'SELECT mfa_locked_until FROM idp_users WHERE id = $1',
    [userId],
  );
  const until = rows[0]?.mfa_locked_until;
  return { locked: Boolean(until && new Date(until) > new Date()) };
}

/** Call after every verifyTotp() check, success or failure — shared by the
 *  login MFA step and self-service enroll/disable (auth/totp.ts has no state
 *  of its own to track attempts against). */
export async function recordMfaAttempt(userId: string, success: boolean): Promise<void> {
  if (success) {
    await pool.query(
      'UPDATE idp_users SET mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() WHERE id = $1',
      [userId],
    );
    return;
  }
  const { rows } = await pool.query<{ mfa_failed_attempts: number; mfa_locked_until: Date | null }>(
    'SELECT mfa_failed_attempts, mfa_locked_until FROM idp_users WHERE id = $1',
    [userId],
  );
  // Same fix as authenticateLocal's password lockout in this file: once a
  // lockout window has fully elapsed, start a fresh window instead of
  // incrementing the stale prior count, or the next failed MFA attempt would
  // instantly re-lock the account for another full window, indefinitely.
  const until = rows[0]?.mfa_locked_until;
  const priorLockExpired = Boolean(until && new Date(until) <= new Date());
  const failed = priorLockExpired ? 1 : (rows[0]?.mfa_failed_attempts ?? 0) + 1;
  const lockedUntil = failed >= MFA_LOCKOUT_THRESHOLD ? new Date(Date.now() + MFA_LOCKOUT_MINUTES * 60_000) : null;
  await pool.query(
    'UPDATE idp_users SET mfa_failed_attempts = $2, mfa_locked_until = $3, updated_at = NOW() WHERE id = $1',
    [userId, failed, lockedUntil],
  );
}

/**
 * Upsert an AD-authenticated user into the unified store so it has a stable
 * account id (uuid `sub`) and findAccount/userinfo/refresh can resolve it later.
 * Password stays null (AD users never local-login); groups are synced from AD.
 */
export async function upsertAdUser(input: {
  email: string;
  emailVerified: boolean;
  givenName: string;
  familyName: string;
  groups: string[];
}): Promise<LocalUser> {
  const { rows } = await pool.query<UserRow>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, source, is_active, last_login_at)
     VALUES ($1, $2, $3, $4, 'ad', TRUE, NOW())
     ON CONFLICT (email) DO UPDATE
       SET email_verified = EXCLUDED.email_verified,
           given_name = EXCLUDED.given_name,
           family_name = EXCLUDED.family_name,
           source = 'ad',
           last_login_at = NOW(),
           updated_at = NOW()
     RETURNING *`,
    [input.email, input.emailVerified, input.givenName, input.familyName],
  );
  const row = rows[0];
  await syncAdGroupMembership(row.id, row.email, input.groups);

  return toLocalUser(row, input.groups);
}

/**
 * Diff a user's AD group set against what's stored, write the new set, and
 * revoke their other live sessions if it narrowed. Shared by upsertAdUser
 * (called at login) and the periodic re-sync sweep (ad-resync.worker.ts) —
 * platform audit finding 4.7: AD group membership used to only ever get
 * rechecked at login, so someone pulled from an elevated/entitled group
 * mid-session kept that access until their 14-day session happened to expire
 * or they logged in again. The periodic sweep calls this same function on a
 * timer so a removal takes effect within that sweep's interval instead.
 * Returns whether a shrink (and therefore a revoke) actually happened.
 */
export async function syncAdGroupMembership(userId: string, email: string, groups: string[]): Promise<boolean> {
  const { rows: existingGroupRows } = await pool.query<{ group_dn: string }>(
    `SELECT group_dn FROM idp_user_groups WHERE user_id = $1`,
    [userId],
  );
  const previousGroups = new Set(existingGroupRows.map((g) => g.group_dn));
  const nextGroups = new Set(groups);
  const groupsShrank = [...previousGroups].some((dn) => !nextGroups.has(dn));

  // Sync group memberships from AD (authoritative each time this runs).
  await pool.query(`DELETE FROM idp_user_groups WHERE user_id = $1`, [userId]);
  for (const dn of groups) {
    await pool.query(
      `INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [userId, dn],
    );
  }

  // AD group membership just narrowed for this user (removed from an
  // app-entitled or elevated-role group, say) — their OTHER already-open
  // sessions were minted under the old, broader group set and must not keep
  // working on stale claims until they happen to expire/refresh. At login
  // this runs before oidc-provider issues a Session for the login currently
  // in progress, so it only clears prior sessions, never the one being
  // created right now. Growing the group set (or no change) needs no
  // action — claims() recomputes fresh on every token issuance anyway.
  if (groupsShrank) {
    await revokeAllSessions(userId, email).catch((err) => {
      logger.error({ err, userId, email }, '[idp:auth] AD group-shrink session revoke failed');
    });
  }

  return groupsShrank;
}

/** Fetch a local user by id (for oidc-provider findAccount). */
export async function getLocalUserById(id: string): Promise<LocalUser | null> {
  const { rows } = await pool.query<UserRow>(`SELECT * FROM idp_users WHERE id = $1`, [id]);
  if (!rows[0]) return null;
  return toLocalUser(rows[0], await loadGroups(rows[0].id));
}

/**
 * Verify local credentials with lockout. Returns the user on success, or a
 * typed failure reason.
 */
export async function authenticateLocal(
  email: string,
  password: string,
): Promise<{ ok: true; user: LocalUser } | { ok: false; reason: 'not_found' | 'locked' | 'inactive' | 'bad_password' }> {
  const { rows } = await pool.query<UserRow>(`SELECT * FROM idp_users WHERE email = $1`, [email]);
  const row = rows[0];
  if (!row) {
    await verifyPassword(password, await getDummyHash());
    return { ok: false, reason: 'not_found' };
  }
  if (!row.is_active) {
    await verifyPassword(password, await getDummyHash());
    return { ok: false, reason: 'inactive' };
  }
  if (row.locked_until && new Date(row.locked_until) > new Date()) {
    await verifyPassword(password, await getDummyHash());
    return { ok: false, reason: 'locked' };
  }

  const good = await verifyPassword(password, row.password_hash);
  if (!good) {
    // If a previous lockout has already elapsed (guaranteed true whenever
    // locked_until is set at all at this point — the check above already
    // returned early while it was still in the future), this failed attempt
    // starts a fresh window instead of incrementing the stale prior count.
    // Without this, the counter never resets on its own (only a SUCCESSFUL
    // login clears it), so the very next typo after a lockout expires would
    // instantly re-lock the account for another full window, indefinitely.
    const priorLockExpired = Boolean(row.locked_until && new Date(row.locked_until) <= new Date());
    const failed = priorLockExpired ? 1 : row.failed_logins + 1;
    const lockUntil = failed >= LOCKOUT_THRESHOLD ? new Date(Date.now() + LOCKOUT_MINUTES * 60_000) : null;
    await pool.query(
      `UPDATE idp_users SET failed_logins = $2, locked_until = $3, updated_at = NOW() WHERE id = $1`,
      [row.id, failed, lockUntil],
    );
    return { ok: false, reason: 'bad_password' };
  }

  await pool.query(
    `UPDATE idp_users SET failed_logins = 0, locked_until = NULL, last_login_at = NOW(), updated_at = NOW() WHERE id = $1`,
    [row.id],
  );
  return { ok: true, user: toLocalUser(row, await loadGroups(row.id)) };
}
