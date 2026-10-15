/**
 * The platform administrator is invisible and untouchable in SSO.
 *
 * To every IdP administrator and every other user, that account does not exist:
 * it is in no user list, group, client roster, session list, sign-in history or
 * audit view; it cannot be disabled, reset, signed out, re-roled, re-grouped or
 * deleted; and a console request that names it answers exactly like a request
 * for an id that was never there (404), so it cannot be probed. Its own sign-ins
 * and sessions are not recorded, so there is nothing to display or to lock it
 * out with. The IdP administrator group is DOWNGRADED relative to it: only the
 * platform administrator may rotate or withdraw signing keys, or change who
 * belongs to the IdP administrator group (see requirePlatformAdminAccount).
 *
 * The database repeats the hard parts (migration 015: triggers refuse changes to
 * the account unless a vault password the owner alone knows is supplied). This
 * module is the application half. Do not add a "show platform admin" switch
 * anywhere; anything that must touch the account goes through the vault
 * (scripts/platform-vault.ts).
 *
 * Identity at rest: when PLATFORM_ADMIN_PEPPER is set, the account is stored
 * under a keyed pseudonym instead of the owner's real email
 * (platformAdminPseudonym), and the login form maps the real email typed by the
 * owner to it. Then even a full read of the database does not say who it is.
 */
import crypto from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { pool } from '../db/pool.js';
import { IDP_CONFIG } from '../config.js';

const TTL_MS = 15_000;
let cache: { ids: string[]; emails: string[]; at: number } | null = null;

interface Snapshot {
  ids: string[];
  /** The stored emails (real or pseudonymous) of every platform admin. */
  emails: string[];
}

async function snapshot(): Promise<Snapshot> {
  if (cache && Date.now() - cache.at < TTL_MS) return cache;
  const { rows } = await pool.query<{ id: string; email: string }>(
    'SELECT id, email FROM idp_users WHERE is_platform_admin',
  );
  cache = { ids: rows.map((r) => r.id), emails: rows.map((r) => r.email.toLowerCase()), at: Date.now() };
  return cache;
}

/** Forget the cached set (after the seed script, or in tests). */
export function invalidatePlatformAdminCache(): void {
  cache = null;
}

export async function platformAdminIds(): Promise<string[]> {
  return (await snapshot()).ids;
}

export async function platformAdminEmails(): Promise<string[]> {
  return (await snapshot()).emails;
}

export async function isPlatformAdminId(id: string | null | undefined): Promise<boolean> {
  if (!id) return false;
  return (await snapshot()).ids.includes(id);
}

export async function isPlatformAdminEmail(email: string | null | undefined): Promise<boolean> {
  if (!email) return false;
  return (await snapshot()).emails.includes(email.trim().toLowerCase());
}

/**
 * The keyed pseudonym stored in place of the real email. HMAC-SHA256 keyed with
 * the pepper, so it cannot be reversed or guessed-and-checked without the pepper
 * AND the candidate address. `.invalid` is a reserved TLD: it can never be a real
 * mailbox, so nothing can ever be sent to it by mistake.
 */
export function platformAdminPseudonym(realEmail: string, pepper: string): string {
  const mac = crypto.createHmac('sha256', pepper).update(realEmail.trim().toLowerCase()).digest('hex');
  return `pa-${mac.slice(0, 32)}@platform.invalid`;
}

export interface PlatformAdminLogin {
  id: string;
  /** The email as stored (the pseudonym when a pepper is in use). */
  email: string;
}

/**
 * If the address typed at the login form belongs to the platform admin, return its row.
 * Matches the stored email directly, or, when a pepper is configured, the pseudonym of
 * the typed address. Used so the account can sign in under its real email while the
 * database never contains it, and so its sign-ins can be kept out of every record.
 */
export async function findPlatformAdminForLogin(typedEmail: string): Promise<PlatformAdminLogin | null> {
  const typed = typedEmail.trim().toLowerCase();
  if (!typed) return null;
  const candidates = [typed];
  if (IDP_CONFIG.platformAdminPepper) candidates.push(platformAdminPseudonym(typed, IDP_CONFIG.platformAdminPepper));
  const { rows } = await pool.query<PlatformAdminLogin>(
    'SELECT id, email FROM idp_users WHERE is_platform_admin AND email = ANY($1::text[]) LIMIT 1',
    [candidates],
  );
  return rows[0] ?? null;
}

/** SQL predicate for raw queries over `idp_users` aliased `alias`: the account is excluded. */
export function visibleUserSql(alias = 'u'): string {
  return `NOT ${alias}.is_platform_admin`;
}

/**
 * Express `router.param('id')` handler for the console's `/users/:id/...` routes:
 * a request naming a platform admin (other than the signed-in one acting on
 * itself) is answered as "user not found", the same as an unknown id.
 */
export function guardPlatformAdminUserParam(
  sendNotFound: (res: Response) => void,
): (req: Request, res: Response, next: NextFunction, id: string) => Promise<void> {
  return async (req, res, next, id) => {
    try {
      if (await isPlatformAdminId(id)) {
        const viewer = (req as Request & { adminSession?: { accountId?: string } }).adminSession?.accountId;
        if (viewer !== id) {
          sendNotFound(res);
          return;
        }
      }
      next();
    } catch (err) {
      next(err);
    }
  };
}

/**
 * Gate for the few console actions that belong to the platform administrator
 * alone (signing keys, who is an IdP administrator). The IdP administrator group
 * opens the console; it does not open these.
 */
export async function isPlatformAdminSession(session: { accountId?: string } | undefined): Promise<boolean> {
  return isPlatformAdminId(session?.accountId);
}

export function requirePlatformAdminAccount(
  sendForbidden: (res: Response) => void,
): RequestHandler {
  return async (req, res, next) => {
    try {
      const session = (req as Request & { adminSession?: { accountId?: string } }).adminSession;
      if (await isPlatformAdminSession(session)) {
        next();
        return;
      }
      sendForbidden(res);
    } catch (err) {
      next(err);
    }
  };
}

/** True for the role name that is never offered, listed or granted through any console. */
export const PLATFORM_ADMIN_ROLE = 'PLATFORM_ADMIN';

export function withoutPlatformAdminRole<T extends { role_name?: string; name?: string }>(rows: readonly T[]): T[] {
  return rows.filter((r) => (r.role_name ?? r.name) !== PLATFORM_ADMIN_ROLE);
}

/** For role-name string lists. */
export function withoutPlatformAdminRoleName(names: readonly string[]): string[] {
  return names.filter((n) => n !== PLATFORM_ADMIN_ROLE);
}

/** SQL sub-selects for raw queries: ids (as text, to compare with JSON payload fields) and lower-cased stored emails. */
export const PA_IDS_SQL = `(SELECT id::text FROM idp_users WHERE is_platform_admin)`;
export const PA_EMAILS_SQL = `(SELECT lower(email) FROM idp_users WHERE is_platform_admin)`;

/** Thrown by the lower-level helpers (addUserToGroup / removeUserFromGroup) when a non-platform-admin tries an action reserved to it. */
export class PlatformAdminOnlyError extends Error {
  constructor() {
    super('This action is reserved to the platform administrator.');
    this.name = 'PlatformAdminOnlyError';
  }
}
