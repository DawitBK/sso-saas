/**
 * Persistent failure counting and escalating lockout for the owner sequence (migration 027, owner_verification_state: one row, one owner).
 *
 * Every wrong answer or code, in any step, counts. After LOCK_AFTER_FAILURES in a row the whole sequence locks, for 5 minutes, then 15 minutes, 1 hour,
 * 6 hours, 24 hours (each lock raises the level; the level falls back to zero after a day with no failure, or at once when the owner completes a
 * run). While locked, nothing is checked at all (a guess made during a lock is not even looked at), so waiting it out is the only way. The counters
 * live in the database so a restart, or a second process, cannot reset them.
 *
 * Honest trade-off: someone holding only a stolen session can keep the owner locked out by failing on purpose. That denies the owner, it never
 * lets the thief in; the way out is `npm run owner:unlock` at the server, and the failure itself is a security event.
 */
import { pool } from '../db/pool.js';
import { LOCK_AFTER_FAILURES, LOCK_SECONDS_BY_LEVEL } from './policy.js';

export interface LockStatus {
  locked: boolean;
  lockedUntil: Date | null;
  retryAfterSeconds: number;
  level: number;
  failures: number;
}

async function ensureRow(): Promise<void> {
  await pool.query('INSERT INTO owner_verification_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING');
}

export async function lockStatus(): Promise<LockStatus> {
  await ensureRow();
  // A day without a failure (and no active lock) wipes the history.
  await pool.query(
    `UPDATE owner_verification_state SET consecutive_failures = 0, lockout_level = 0, updated_at = NOW()
      WHERE id = 1 AND (consecutive_failures > 0 OR lockout_level > 0)
        AND last_failure_at < NOW() - INTERVAL '24 hours' AND (locked_until IS NULL OR locked_until < NOW())`,
  );
  const { rows } = await pool.query<{ locked_until: Date | null; lockout_level: number; consecutive_failures: number; secs: number }>(
    `SELECT locked_until, lockout_level, consecutive_failures, GREATEST(0, CEIL(EXTRACT(EPOCH FROM (locked_until - NOW()))))::int AS secs
       FROM owner_verification_state WHERE id = 1`,
  );
  const r = rows[0];
  const locked = Boolean(r?.locked_until) && (r?.secs ?? 0) > 0;
  return {
    locked,
    lockedUntil: locked ? (r?.locked_until ?? null) : null,
    retryAfterSeconds: locked ? (r?.secs ?? 0) : 0,
    level: r?.lockout_level ?? 0,
    failures: r?.consecutive_failures ?? 0,
  };
}

export interface FailureResult {
  locked: boolean;
  retryAfterSeconds: number;
  attemptsLeft: number;
}

/** Count one failure, atomically; lock when the threshold is reached. */
export async function recordFailure(): Promise<FailureResult> {
  await ensureRow();
  const { rows } = await pool.query<{ consecutive_failures: number; locked_now: boolean; secs: number }>(
    `UPDATE owner_verification_state SET
        consecutive_failures = CASE WHEN consecutive_failures + 1 >= $1 THEN 0 ELSE consecutive_failures + 1 END,
        locked_until = CASE WHEN consecutive_failures + 1 >= $1
                            THEN NOW() + make_interval(secs => ($2::int[])[LEAST(lockout_level + 1, array_length($2::int[], 1))])
                            ELSE locked_until END,
        lockout_level = CASE WHEN consecutive_failures + 1 >= $1 THEN lockout_level + 1 ELSE lockout_level END,
        last_failure_at = NOW(),
        updated_at = NOW()
      WHERE id = 1
      RETURNING consecutive_failures, (consecutive_failures = 0) AS locked_now,
                GREATEST(0, CEIL(EXTRACT(EPOCH FROM (locked_until - NOW()))))::int AS secs`,
    [LOCK_AFTER_FAILURES, [...LOCK_SECONDS_BY_LEVEL]],
  );
  const r = rows[0];
  const lockedNow = Boolean(r?.locked_now);
  return {
    locked: lockedNow,
    retryAfterSeconds: lockedNow ? (r?.secs ?? 0) : 0,
    attemptsLeft: lockedNow ? 0 : Math.max(0, LOCK_AFTER_FAILURES - (r?.consecutive_failures ?? 0)),
  };
}

/** The owner completed a whole run: forget the failures and the escalation. */
export async function recordRunSuccess(): Promise<void> {
  await ensureRow();
  await pool.query('UPDATE owner_verification_state SET consecutive_failures = 0, lockout_level = 0, locked_until = NULL, updated_at = NOW() WHERE id = 1');
}

/** Operator action at the server (`npm run owner:unlock`). */
export async function clearLock(): Promise<void> {
  await recordRunSuccess();
}

/**
 * Accept an authenticator time step only if it is newer than every one accepted before (replay protection). Atomic: of two requests carrying the
 * same code, exactly one gets true.
 */
export async function acceptTotpStep(step: number): Promise<boolean> {
  await ensureRow();
  const res = await pool.query('UPDATE owner_verification_state SET totp_last_step = $1, updated_at = NOW() WHERE id = 1 AND totp_last_step < $1', [step]);
  return res.rowCount === 1;
}
