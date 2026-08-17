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

import type { Account, AccountClaims, FindAccount } from 'oidc-provider';
import { AD_GROUPS_CLAIM } from '../config.js';
import { pool } from '../db/pool.js';
import { authenticateAD, isAdEnabled } from './ldap.service.js';
import { authenticateLocal, getLocalUserById, upsertAdUser, type LocalUser } from './local-users.js';
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
const AD_LOCKOUT_THRESHOLD = 5;
async function recentFailureCount(email: string): Promise<number> {
  const { rows } = await pool.query<{ count: string }>(
    `SELECT COUNT(*) FROM idp_login_events
     WHERE email = $1 AND success = FALSE AND reason != 'locked' AND created_at > NOW() - INTERVAL '15 minutes'`,
    [email],
  );
  return Number(rows[0]?.count ?? 0);
}

export type AuthResult =
  | { ok: true; accountId: string; mustChangePassword: boolean }
  | { ok: false; reason: 'invalid_credentials' | 'locked' | 'inactive' };

async function claimsFor(user: LocalUser): Promise<AccountClaims> {
  const name = [user.givenName, user.familyName].filter(Boolean).join(' ').trim();
  const roleClaims = await resolveClientRoleClaims(user.email, user.groups);
  return {
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    given_name: user.givenName,
    family_name: user.familyName,
    name: name || user.email,
    [AD_GROUPS_CLAIM]: user.groups,
    [GMS_ROLES_CLAIM]: roleClaims[GMS_ROLES_CLAIM],
    [EDAMS_ROLES_CLAIM]: roleClaims[EDAMS_ROLES_CLAIM],
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
export async function authenticateUser(email: string, password: string): Promise<AuthResult> {
  const normalizedEmail = email.trim().toLowerCase();

  if (await recentFailureCount(normalizedEmail) >= AD_LOCKOUT_THRESHOLD) {
    return { ok: false, reason: 'locked' };
  }

  // 1) AD-primary
  if (isAdEnabled()) {
    try {
      const ad = await authenticateAD(email.trim(), password);
      if (ad) {
        const user = await upsertAdUser({
          email: ad.email.toLowerCase(),
          emailVerified: ad.emailVerified,
          givenName: ad.givenName,
          familyName: ad.familyName,
          groups: ad.adGroups,
        });
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
  const local = await authenticateLocal(normalizedEmail, password);
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

/** Resolve claims by accountId (used by the portal/bridge). */
export async function getIdentity(accountId: string): Promise<LocalUser | null> {
  return getLocalUserById(accountId);
}
