/**
 * Unified authentication (AD-primary, local fallback) and the oidc-provider
 * Account contract.
 *
 * - authenticateUser(): tries AD bind first; on success upserts into the unified
 *   store (stable uuid `sub`). If AD is disabled or doesn't know the user, falls
 *   back to the local Postgres user store. Returns a normalized identity.
 * - findAccount(): oidc-provider hook that rebuilds an Account (and its claims)
 *   from just the stored accountId — used for the SSO session, refresh, userinfo.
 */

import { findPlatformAdminForLogin } from './platform-admin.js';
import type { Account, AccountClaims, FindAccount } from 'oidc-provider';
import { AD_GROUPS_CLAIM } from '../config.js';
import { getBool, getNumber } from '../settings/store.js';
import { pool } from '../db/pool.js';
import { authenticateAD, isAdEnabled } from './ldap.service.js';
import { AdAccountCollisionError, authenticateLocal, getLocalUserById, upsertAdUser, type LocalUser } from './local-users.js';
import { logger } from '../logging/logger.js';
import {
  EDAMS_ROLES_CLAIM,
  GMS_ROLES_CLAIM,
  resolveClientRoleClaims,
} from './client-role-claims.js';

// idp_login_events is the only signal shared by both auth paths — the local
// store has its own column-based lockout (auth/local-users.ts), but AD binds
// aren't throttled by anything, here or at AD itself. Gate on recent failures
// regardless of source so an AD-only account gets brute-force protection too.
//
// Deliberately excludes reason = 'locked': that reason is written by THIS
// check's own past outcome, not a real credential failure. Counting it would
// make every retry against an already-locked account log another qualifying
// row, pushing the 15-minute window forward forever — a lockout that can
// never expire while anyone (or an automated caller) keeps trying it.
// Failures before a lock, and the window they are counted in: platform settings lockout.threshold / lockout.minutes
// (settings/registry.ts), read at each sign-in so a change applies at once.
const lockoutThreshold = (): number => getNumber('lockout.threshold');
const lockoutWindowMinutes = (): number => getNumber('lockout.minutes');

/**
 * P1-17 — the lockout is now two-dimensional.
 *
 * It used to be a single `COUNT(*) WHERE email = $1`: five wrong guesses against
 * any address a stranger knew locked that person out of the SSO IdP — and
 * therefore out of DMS, GMS, the portal, everything — for fifteen minutes,
 * repeatable indefinitely. Knowing a colleague's email address was a complete,
 * unauthenticated denial of service against them, and the platform had no way to
 * tell it apart from a real brute-force attempt.
 *
 * The email dimension is kept, because it is the one that actually stops a
 * password-guessing attack. What changed is that it only locks when the failures
 * are CONCENTRATED — one source hammering one account, which is what a real
 * attack looks like — and a separate per-IP ceiling covers the other shape, one
 * source spraying many accounts.
 *
 * The honest trade-off: an attacker who can spread guesses across more than
 * LOCKOUT_MAX_DISTINCT_IPS addresses now gets lockout.threshold attempts per
 * address instead of five in total. That is deliberate — the alternative is
 * leaving a trivially-triggered platform-wide DoS in place — and it is bounded on
 * three sides: IP_LOCKOUT_THRESHOLD caps any single source regardless of which
 * accounts it targets, EMAIL_ALERT_THRESHOLD raises a loud alert well before a
 * distributed attempt gets far, and for LOCAL accounts authenticateLocal's own
 * per-row `failed_logins`/`locked_until` lock still applies — this gate only
 * decides whether that row-level lock is allowed to be set (see its
 * `mayLockAccount` parameter), so a concentrated attack still hard-locks the row
 * exactly as before.
 */
const LOCKOUT_MAX_DISTINCT_IPS = 2;
const EMAIL_ALERT_THRESHOLD = 20;
const IP_LOCKOUT_THRESHOLD = 50;

/**
 * Reasons written by this gate itself, not by a real credential failure.
 * Excluded from the counts for the reason the original comment gave: counting
 * them makes every retry against an already-locked account log another
 * qualifying row, pushing the 15-minute window forward forever — a lockout that
 * can never expire while anyone keeps trying it.
 */
const SELF_INFLICTED_REASONS = "('locked', 'locked_ip', 'account_conflict', 'mfa_unavailable')";

interface FailureStats {
  /** Failures for this email, from anywhere. */
  email: number;
  /** How many distinct source addresses those came from. */
  distinctIps: number;
  /** Failures for this exact (email, ip) pair. */
  pair: number;
  /** Failures from this IP against any account. */
  ip: number;
}

/**
 * When this account's failed-attempt window was last wiped (an admin password reset, a password
 * change, or a successful sign-in). Failures at or before it no longer count. Without it a reset
 * cleared the row counters but the correct new password was still refused as 'locked' until the
 * 15-minute event window drained by itself.
 */
async function failuresClearedAt(email: string): Promise<Date> {
  const { rows } = await pool.query<{ login_failures_cleared_at: Date | null }>(
    'SELECT login_failures_cleared_at FROM idp_users WHERE lower(btrim(email)) = $1 ORDER BY (email = $1) DESC LIMIT 1',
    [email],
  );
  return rows[0]?.login_failures_cleared_at ?? new Date(0);
}

async function recentFailureStats(email: string, ip: string, clearedAt: Date): Promise<FailureStats> {
  const windowMinutes = lockoutWindowMinutes();
  const { rows } = await pool.query<{ email_failures: string; distinct_ips: string; pair_failures: string; ip_failures: string }>(
    `SELECT
       COUNT(*)           FILTER (WHERE email = $1 AND created_at > $3)               AS email_failures,
       COUNT(DISTINCT ip) FILTER (WHERE email = $1 AND created_at > $3)               AS distinct_ips,
       COUNT(*)           FILTER (WHERE email = $1 AND ip = $2 AND created_at > $3)   AS pair_failures,
       COUNT(*)           FILTER (WHERE ip = $2)                  AS ip_failures
     FROM idp_login_events
     WHERE success = FALSE
       AND reason NOT IN ${SELF_INFLICTED_REASONS}
       AND created_at > NOW() - make_interval(mins => $4::int)
       AND (email = $1 OR ip = $2)`,
    [email, ip, clearedAt, windowMinutes],
  );
  const r = rows[0];
  return {
    email: Number(r?.email_failures ?? 0),
    distinctIps: Number(r?.distinct_ips ?? 0),
    pair: Number(r?.pair_failures ?? 0),
    ip: Number(r?.ip_failures ?? 0),
  };
}

type LockoutDecision =
  | { locked: true; reason: 'locked' | 'locked_ip' }
  | { locked: false; concentrated: boolean };

async function evaluateLockout(email: string, ip: string): Promise<LockoutDecision> {
  // Owner decision 2026-10-09: no password lockout (LOGIN_LOCKOUT_ENABLED=false, the default).
  // Failures are still written to idp_login_events by the caller; nothing here refuses a sign-in
  // and no hard lock is set on the row (concentrated=false makes authenticateLocal skip it).
  if (!getBool('lockout.enabled')) return { locked: false, concentrated: false };
  const clearedAt = await failuresClearedAt(email);
  // An unknown source address (no req.ip, a malformed proxy header) cannot be
  // used as a lockout dimension without letting an attacker opt out of the
  // per-IP ceiling by suppressing it. Fall back to the old email-only behaviour
  // in that case: strictly safer, and it should not happen behind the Apache
  // edge, which always sets a forwarded address.
  if (!ip) {
    // Keyed on the email alone. Passing an empty string as the IP would instead
    // match every row whose `ip` column is empty, conflating unrelated attempts
    // into the per-IP ceiling.
    const { rows } = await pool.query<{ count: string }>(
      `SELECT COUNT(*) FROM idp_login_events
       WHERE email = $1 AND success = FALSE
         AND reason NOT IN ${SELF_INFLICTED_REASONS}
         AND created_at > NOW() - make_interval(mins => $3::int)
         AND created_at > $2`,
      [email, clearedAt, lockoutWindowMinutes()],
    );
    if (Number(rows[0]?.count ?? 0) >= lockoutThreshold()) return { locked: true, reason: 'locked' };
    return { locked: false, concentrated: true };
  }

  const stats = await recentFailureStats(email, ip, clearedAt);

  if (stats.ip >= IP_LOCKOUT_THRESHOLD) {
    logger.error(
      { ip, ipFailures: stats.ip },
      '[idp:auth:ALERT] source address exceeded the per-IP failed-login ceiling across all accounts — credential stuffing or a broken client. Blocked at the IdP; consider blocking it at the edge.',
    );
    return { locked: true, reason: 'locked_ip' };
  }

  // Concentrated: one source, one account. The realistic brute-force shape, and
  // the one the original per-email lock was actually catching.
  if (stats.pair >= lockoutThreshold()) return { locked: true, reason: 'locked' };

  // Still lock on the email dimension when the failures came from at most a
  // couple of addresses — a real person retyping a password from their desk and
  // their phone, or an attacker on a small number of hosts. This keeps today's
  // behaviour for every non-adversarial case.
  if (stats.email >= lockoutThreshold() && stats.distinctIps <= LOCKOUT_MAX_DISTINCT_IPS) {
    return { locked: true, reason: 'locked' };
  }

  if (stats.email >= EMAIL_ALERT_THRESHOLD) {
    logger.error(
      { email, emailFailures: stats.email, distinctIps: stats.distinctIps },
      '[idp:auth:ALERT] many failed logins for one account from many distinct addresses — distributed brute force, or someone trying to weaponize the lockout against this user. NOT locked (that is the DoS this avoids); investigate the source addresses.',
    );
  }

  // `concentrated` tells authenticateLocal whether a hard row-level lock is
  // warranted if the password turns out to be wrong. Distributed failures raise
  // the alert above instead of locking the account.
  return { locked: false, concentrated: stats.distinctIps <= LOCKOUT_MAX_DISTINCT_IPS };
}

export type AuthResult =
  | {
      ok: true;
      accountId: string;
      mustChangePassword: boolean;
      /** The platform administrator signed in: nothing about this attempt is recorded. */
      platformAdmin?: boolean;
    }
  | {
      ok: false;
      /** The address typed belongs to the platform administrator: nothing about this attempt is recorded. */
      platformAdmin?: boolean;
      reason:
        | 'invalid_credentials'
        | 'locked'
        // Per-IP ceiling, not per-account: this source is blocked, the account
        // itself is not. Recorded distinctly so admins can tell the two apart in
        // /admin/logins instead of seeing an account that looks compromised.
        | 'locked_ip'
        | 'inactive'
        // AD credentials were correct, but the email belongs to a local account
        // (see AdAccountCollisionError). Needs an admin, not a retry.
        | 'account_conflict';
    };

async function claimsFor(user: LocalUser): Promise<AccountClaims> {
  const name = [user.givenName, user.familyName].filter(Boolean).join(' ').trim();
  const roleClaims = await resolveClientRoleClaims(user.email, user.groups);
  const edamsRoles = roleClaims[EDAMS_ROLES_CLAIM];
  return {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    given_name: user.givenName,
    family_name: user.familyName,
    name: name || user.email,
    [AD_GROUPS_CLAIM]: user.groups,
    [GMS_ROLES_CLAIM]: roleClaims[GMS_ROLES_CLAIM],
    // OMITTED, not defaulted, when DMS role resolution failed — see
    // resolveEdamsRolesFromGroups. DMS treats a present, non-empty roles claim
    // as authoritative over its own local user_roles table, so asserting a
    // fabricated EMPLOYEE default here silently demoted real users whenever
    // DMS's internal API blipped. Absence lets DMS's own fallback chain run.
    ...(edamsRoles ? { [EDAMS_ROLES_CLAIM]: edamsRoles } : {}),
  };
}

function toAccount(user: LocalUser): Account {
  return {
    accountId: user.id,
    // oidc-provider calls this to populate id_token / userinfo per requested scope.
    async claims(): Promise<AccountClaims> {
      return claimsFor(user);
    },
  };
}

/**
 * Verify credentials from the login form. AD first, then local.
 * Returns a stable accountId that oidc-provider persists in the session.
 */
export async function authenticateUser(email: string, password: string, ip = ''): Promise<AuthResult> {
  const normalizedEmail = email.trim().toLowerCase();

  // The platform administrator signs in under its real address while the database
  // may only hold a keyed pseudonym of it (auth/platform-admin.ts). Its attempts
  // are never written to idp_login_events, so the failure-count gate below has
  // nothing to count and it can never be locked out; and it is local-only, so an
  // AD server cannot be used to probe or shadow it.
  const pa = await findPlatformAdminForLogin(normalizedEmail);
  if (pa) {
    const local = await authenticateLocal(pa.email, password, false);
    if (local.ok) {
      return { ok: true, accountId: local.user.id, mustChangePassword: local.user.mustChangePassword, platformAdmin: true };
    }
    return {
      ok: false,
      platformAdmin: true,
      reason: local.reason === 'inactive' ? 'inactive' : local.reason === 'locked' ? 'locked' : 'invalid_credentials',
    };
  }

  const lockout = await evaluateLockout(normalizedEmail, ip);
  if (lockout.locked) return { ok: false, reason: lockout.reason };

  // 1) AD-primary
  if (isAdEnabled()) {
    try {
      const ad = await authenticateAD(email.trim(), password);
      if (ad) {
        let user: LocalUser;
        try {
          user = await upsertAdUser({
            email: ad.email.toLowerCase(),
            emailVerified: ad.emailVerified,
            givenName: ad.givenName,
            familyName: ad.familyName,
            groups: ad.adGroups,
          });
        } catch (err) {
          // Correct AD password, but the email is owned by a local account.
          // upsertAdUser already logged the ALERT and left the row untouched.
          // Return rather than fall through to the local path: falling through
          // would try the AD password against the LOCAL account's hash, and a
          // failure there would count toward that innocent account's lockout.
          if (err instanceof AdAccountCollisionError) return { ok: false, reason: 'account_conflict' };
          throw err;
        }
        // The IdP-side disable switch applies to AD users too — valid AD
        // credentials must not resurrect an account an admin turned off.
        if (!user.isActive) return { ok: false, reason: 'inactive' };
        return { ok: true, accountId: user.id, mustChangePassword: false };
      }
      // AD reachable but rejected credentials — still allow local fallback for
      // non-AD (service) accounts with the same email.
    } catch (err) {
      // Any AD problem lands here — a real bind rejection above returns `ad ===
      // null` and never reaches this catch; this is a network blip, timeout, or
      // an expired/broken service-account bind, i.e. every login in the building
      // silently downgrading to the weaker local path. error (not warn) so it's
      // not lost in normal noise — there is no metrics/alerting pipeline this
      // feeds today, so a human still has to be watching logs for it.
      logger.error(
        { err },
        '[idp:auth:ALERT] AD bind error — falling back to local auth, verify AD/service-account health',
      );
    }
  }

  // 2) Local fallback
  // `lockout.concentrated` gates the row-level lock — see authenticateLocal's
  // mayLockAccount parameter and the note on evaluateLockout above.
  const local = await authenticateLocal(normalizedEmail, password, lockout.concentrated);
  if (local.ok) return { ok: true, accountId: local.user.id, mustChangePassword: local.user.mustChangePassword };
  if (local.reason === 'locked') return { ok: false, reason: 'locked' };
  if (local.reason === 'inactive') return { ok: false, reason: 'inactive' };
  return { ok: false, reason: 'invalid_credentials' };
}

/** oidc-provider findAccount hook. */
export const findAccount: FindAccount = async (_ctx, id) => {
  const user = await getLocalUserById(id);
  if (!user || !user.isActive) return undefined;
  return toAccount(user);
};
