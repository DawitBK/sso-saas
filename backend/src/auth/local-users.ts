/**
 * Local user store (fallback identity source). AD-primary means most users are
 * NOT here; this covers service accounts / non-AD users. Group memberships are
 * expressed as AD-style DNs so the issued token's `ad_groups` claim looks the
 * same regardless of source.
 */

import crypto from 'node:crypto';
import { pool } from '../db/pool.js';
import { hashPassword, needsRehash, verifyPassword } from './password.js';
import { decryptTotpSecret, encryptTotpSecret, TotpSecretUndecryptableError } from './totp.js';
import { revokeAllSessions } from './revoke.js';
import { logger } from '../logging/logger.js';
import { getBool, getNumber } from '../settings/store.js';
import { clearRecoveryCodes } from './recovery-codes.js';
import { clipName } from '../admin/user-input.js';

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

/**
 * Thrown by upsertAdUser when the AD identity's email is already owned by a
 * non-AD (local) row. Distinct from a credential failure: the AD password was
 * correct, but binding that identity to the existing row would hand over
 * another account's id/`sub` and entitlements. An admin has to resolve it.
 */
export class AdAccountCollisionError extends Error {
  constructor(public readonly email: string) {
    super(`Email ${email} is already owned by a non-AD account`);
    this.name = 'AdAccountCollisionError';
  }
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

// Platform settings lockout.threshold / lockout.minutes (settings/registry.ts), read at each failure so a change applies at once.
const lockoutThreshold = (): number => getNumber('lockout.threshold');
const lockoutMinutes = (): number => getNumber('lockout.minutes');

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
  login_failures_cleared_at: Date | null;
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
     SET password_hash = $2, must_change_password = FALSE, failed_logins = 0, locked_until = NULL,
         login_failures_cleared_at = NOW(), updated_at = NOW()
     WHERE id = $1`,
    [userId, passwordHash],
  );
}

// ── TOTP / MFA state ─────────────────────────────────────────────────────────

export interface TotpState {
  enabled: boolean;
  secret: string | null;
  /** Highest time-step counter already accepted; null = never verified. */
  lastCounter: number | null;
  /**
   * True when the row HAS an encrypted secret that the configured key cannot
   * decrypt (P1-4). Callers must treat this as "MFA is broken for this account"
   * and must NOT record a failed attempt — that is precisely the loop that
   * silently locked out every enrolled user after a key change.
   */
  secretUndecryptable: boolean;
}

export async function getTotpState(userId: string): Promise<TotpState> {
  const { rows } = await pool.query<{ totp_enabled: boolean; totp_secret: string | null; totp_last_counter: string | null }>(
    'SELECT totp_enabled, totp_secret, totp_last_counter FROM idp_users WHERE id = $1',
    [userId],
  );
  const row = rows[0];
  const lastCounter = row?.totp_last_counter == null ? null : Number(row.totp_last_counter);
  if (!row?.totp_secret) {
    return { enabled: row?.totp_enabled ?? false, secret: null, lastCounter, secretUndecryptable: false };
  }
  try {
    return { enabled: row.totp_enabled, secret: decryptTotpSecret(row.totp_secret), lastCounter, secretUndecryptable: false };
  } catch (err) {
    if (err instanceof TotpSecretUndecryptableError) {
      // decryptTotpSecret already logged the ALERT and bumped the metric.
      return { enabled: row.totp_enabled, secret: null, lastCounter, secretUndecryptable: true };
    }
    throw err;
  }
}

/**
 * `usedCounter` is the time-step the enrollment-confirmation code matched. It is
 * stored as the initial replay high-water mark so the very code the user just
 * proved possession of cannot immediately be replayed at the login MFA prompt —
 * the two flows are seconds apart and share the ±1 step window.
 */
export async function enableTotp(userId: string, secret: string, usedCounter: number): Promise<void> {
  await pool.query(
    'UPDATE idp_users SET totp_secret = $2, totp_enabled = TRUE, totp_last_counter = $3, updated_at = NOW() WHERE id = $1',
    [userId, encryptTotpSecret(secret), usedCounter],
  );
}

export async function disableTotp(userId: string): Promise<void> {
  // totp_last_counter goes too: it is meaningless without a secret, and leaving
  // a stale high-water mark behind would reject valid codes from a NEW secret
  // enrolled within the same time step after a re-enroll.
  await pool.query(
    'UPDATE idp_users SET totp_secret = NULL, totp_enabled = FALSE, totp_last_counter = NULL, mfa_failed_attempts = 0, mfa_locked_until = NULL, updated_at = NOW() WHERE id = $1',
    [userId],
  );
  // Recovery codes belong to the authenticator they stand in for: with it gone they must go too (a re-enrol issues a new set).
  await clearRecoveryCodes(userId);
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
 *  of its own to track attempts against).
 *
 *  Returns { replay: true } when usedCounter was supplied but had already been
 *  claimed by a concurrent request by the time this UPDATE ran — see the
 *  WHERE clause below. Callers that pass a usedCounter MUST check this and
 *  treat replay:true as a failed attempt; the caller's own pre-check
 *  (comparing against a value read moments earlier) is a cheap fast path, not
 *  a substitute for this atomic gate. */
export async function recordMfaAttempt(userId: string, success: boolean, usedCounter?: number): Promise<{ replay: boolean }> {
  if (success) {
    // The replay high-water mark advances in the SAME statement that clears the
    // failure counter, so there is no window in which a code is accepted but its
    // counter is not yet burned. The WHERE clause is the actual replay guard —
    // two concurrent requests racing to accept the same still-valid code (the
    // ±1 step window in verifyTotp keeps a code valid for up to ~90s) both read
    // the same pre-update totp_last_counter, but only the one whose UPDATE
    // commits first can satisfy "$2 > totp_last_counter"; the second sees
    // rowCount 0 and must be told replay:true instead of silently succeeding.
    const result = await pool.query(
      `UPDATE idp_users
          SET mfa_failed_attempts = 0,
              mfa_locked_until = NULL,
              totp_last_counter = $2::bigint,
              updated_at = NOW()
        WHERE id = $1
          AND ($2::bigint IS NULL OR totp_last_counter IS NULL OR $2::bigint > totp_last_counter)`,
      [userId, usedCounter ?? null],
    );
    if ((usedCounter ?? null) !== null && result.rowCount === 0) {
      return { replay: true };
    }
    return { replay: false };
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
  return { replay: false };
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
  /**
   * Collision guard (P1-17).
   *
   * This used to be an unconditional `ON CONFLICT (email) DO UPDATE ... SET
   * source = 'ad'`. Any AD account whose `mail` happened to match an existing
   * LOCAL row took that row over: same `id`, and therefore the same OIDC `sub`
   * every relying party has already keyed its own records on. Groups were
   * overwritten from AD, `source` flipped to 'ad' — and `password_hash` was left
   * alone, so the local credential kept working on a row `canSelfChangePassword`
   * now refused to manage. Two live credentials, one identity, and the AD side
   * inheriting whatever the local account was entitled to. For a service account
   * that is a privilege handover triggered by nothing more than an address match.
   *
   * Now: a conflicting row that is `source = 'local'` is refused outright and
   * left untouched, for an admin to resolve deliberately. Only an existing 'ad'
   * row is updated, and its `password_hash` is explicitly nulled so the
   * "AD rows never carry a local credential" invariant is enforced rather than
   * assumed (any non-null hash on an 'ad' row is a leftover from the old
   * takeover behaviour and is exactly the second credential that must not live).
   */
  const { rows: existing } = await pool.query<{ id: string; source: string; password_hash: string | null }>(
    'SELECT id, source, password_hash FROM idp_users WHERE email = $1',
    [input.email],
  );
  const prior = existing[0];
  if (prior && prior.source !== 'ad') {
    logger.error(
      { email: input.email, userId: prior.id, source: prior.source },
      '[idp:auth:ALERT] AD login refused: this email already belongs to a non-AD (local) account. The AD identity would otherwise take over that row, its id/sub, and its entitlements. Resolve the collision deliberately — rename or delete one of the two accounts.',
    );
    throw new AdAccountCollisionError(input.email);
  }
  if (prior?.password_hash) {
    logger.warn(
      { email: input.email, userId: prior.id },
      '[idp:auth] clearing a residual local password_hash from an AD-sourced account — a second, IdP-only credential that survived AD password rotation and account disable',
    );
  }

  const { rows } = await pool.query<UserRow>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, source, is_active, last_login_at)
     VALUES ($1, $2, $3, $4, 'ad', TRUE, NOW())
     ON CONFLICT (email) DO UPDATE
       SET email_verified = EXCLUDED.email_verified,
           given_name = EXCLUDED.given_name,
           family_name = EXCLUDED.family_name,
           source = 'ad',
           password_hash = NULL,
           last_login_at = NOW(),
           updated_at = NOW()
     WHERE idp_users.source = 'ad'
     RETURNING *`,
    // A name read from the directory is cut to the stored length (idp_users_name_length): a long name must never be the reason someone cannot sign in.
    [input.email, input.emailVerified, clipName(input.givenName), clipName(input.familyName)],
  );
  const row = rows[0];
  // The `WHERE idp_users.source = 'ad'` above means DO UPDATE can now match zero
  // rows: the pre-check found no collision, but another request converted or
  // inserted a non-AD row for this email in between. Fail the login rather than
  // dereferencing undefined (which previously could not happen).
  if (!row) {
    logger.error(
      { email: input.email },
      '[idp:auth:ALERT] AD upsert matched an existing non-AD row for this email (raced with the pre-check) — login refused, row left untouched',
    );
    throw new AdAccountCollisionError(input.email);
  }
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
  // The per-user group `CN=user:<id>` carries the DMS/GMS access an administrator assigned in SSO; it is never an AD
  // group, so the AD sync neither counts it as lost nor deletes it.
  const previousGroups = new Set(existingGroupRows.map((g) => g.group_dn).filter((dn) => !dn.startsWith('CN=user:')));
  const nextGroups = new Set(groups);
  const groupsShrank = [...previousGroups].some((dn) => !nextGroups.has(dn));

  /**
   * Sync group memberships from AD (authoritative each time this runs), in ONE
   * transaction and ONE statement.
   *
   * WHY THE TRANSACTION IS LOAD-BEARING: this was a bare DELETE followed by a
   * per-DN INSERT loop with no transaction, so between the DELETE committing
   * and the last INSERT landing, the user genuinely had ZERO groups in the
   * database. Any concurrent read in that window — and the hottest reader on
   * the platform is `findAccount`, which oidc-provider calls on every token
   * issuance, refresh and /userinfo — saw an empty group set and resolved roles
   * to the `guest` / `EMPLOYEE` defaults. Since this function runs on EVERY AD
   * login, a second tab, a token refresh, or the AD-resync worker landing in
   * that window silently minted a downgraded token. Wrapping it means readers
   * see the old set until commit and the new set after, never neither.
   *
   * The loop also became one statement: `unnest` does the whole set in a single
   * round-trip instead of one per group DN (a user in 30 AD groups was 31
   * round-trips inside the login path).
   */
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM idp_user_groups WHERE user_id = $1 AND group_dn NOT LIKE 'CN=user:%'`, [userId]);
    if (groups.length > 0) {
      await client.query(
        `INSERT INTO idp_user_groups (user_id, group_dn)
         SELECT $1, dn FROM unnest($2::text[]) AS dn
         ON CONFLICT DO NOTHING`,
        [userId, groups],
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
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
/**
 * `mayLockAccount` (P1-17): whether this failure is allowed to set a hard
 * `locked_until` on the row.
 *
 * `failed_logins` still increments unconditionally — it is a real signal and
 * admins see it. But the row-level LOCK is the denial-of-service primitive: it
 * was reachable by five wrong guesses against any known address, from anywhere,
 * repeatable forever, and it locks the account out of every system on the
 * platform at once. The caller (authenticateUser) decides, from the shared
 * idp_login_events history, whether the recent failures are CONCENTRATED enough
 * for a lock to be the right response — see evaluateLockout in auth/account.ts.
 * Defaults to true so any future caller is fail-safe rather than fail-open.
 */
export async function authenticateLocal(
  email: string,
  password: string,
  mayLockAccount = true,
): Promise<{ ok: true; user: LocalUser } | { ok: false; reason: 'not_found' | 'locked' | 'inactive' | 'bad_password' }> {
  // Match the stored address case- and whitespace-insensitively: the caller passes it lower-cased
  // and trimmed, but a row written by an import or an older admin form may not be, and such an
  // account could otherwise never sign in whatever its password. Exact match wins a tie.
  const { rows } = await pool.query<UserRow>(
    `SELECT * FROM idp_users WHERE lower(btrim(email)) = $1 ORDER BY (email = $1) DESC LIMIT 1`,
    [email.trim().toLowerCase()],
  );
  const row = rows[0];
  if (!row) {
    await verifyPassword(password, await getDummyHash());
    return { ok: false, reason: 'not_found' };
  }
  if (!row.is_active) {
    await verifyPassword(password, await getDummyHash());
    return { ok: false, reason: 'inactive' };
  }
  if (getBool('lockout.enabled') && row.locked_until && new Date(row.locked_until) > new Date()) {
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
    const lockUntil = getBool('lockout.enabled') && failed >= lockoutThreshold() && mayLockAccount
      ? new Date(Date.now() + lockoutMinutes() * 60_000)
      : null;
    await pool.query(
      `UPDATE idp_users SET failed_logins = $2, locked_until = $3, updated_at = NOW() WHERE id = $1`,
      [row.id, failed, lockUntil],
    );
    return { ok: false, reason: 'bad_password' };
  }

  await pool.query(
    `UPDATE idp_users SET failed_logins = 0, locked_until = NULL, login_failures_cleared_at = NOW(),
            last_login_at = NOW(), updated_at = NOW() WHERE id = $1`,
    [row.id],
  );

  /**
   * P2-9 item 7: opportunistic rehash at the current scrypt cost.
   *
   * This is the only moment the plaintext is available AND known correct, so it
   * is the only place a stored hash can be strengthened without a password
   * reset. Legacy 3-field hashes (no cost parameters) and hashes made at a lower
   * N migrate one successful login at a time — no flag day, no mass invalidation.
   *
   * Best-effort on purpose: a failure here must not fail a login that has already
   * succeeded. The old hash stays valid, and the next login tries again.
   */
  if (needsRehash(row.password_hash)) {
    try {
      const upgraded = await hashPassword(password);
      await pool.query('UPDATE idp_users SET password_hash = $2, updated_at = NOW() WHERE id = $1', [row.id, upgraded]);
      logger.info({ userId: row.id }, 'password hash upgraded to the current scrypt cost on successful login');
    } catch (err) {
      logger.warn({ err, userId: row.id }, 'password rehash after login failed — the existing hash remains valid');
    }
  }

  return { ok: true, user: toLocalUser(row, await loadGroups(row.id)) };
}
