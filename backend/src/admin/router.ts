/**
 * Admin console — manage local IdP users, their group memberships, which apps a
 * group is entitled to open (idp_app_entitlements), and each app's role for that
 * group (idp_role_mappings in DMS's own DB, idp_gms_role_mappings in the IdP's).
 *
 * Gated to members of IDP_CONFIG.adminGroup — the same idp_user_groups membership
 * used everywhere else, no separate permission system for admins themselves.
 */

import crypto from 'node:crypto';
import express, { Router, type Request, type Response, type NextFunction } from 'express';
import type Provider from 'oidc-provider';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';
import { pool } from '../db/pool.js';
import { hashPassword } from '../auth/password.js';
import { revokeAllSessions } from '../auth/revoke.js';
import { disableTotp } from '../auth/local-users.js';
import { generateSigningKey, listSigningKeys, retireSigningKey, reloadProviderKeys } from '../jwks.js';
import { getPortalSession, type PortalSession } from '../portal/session.js';
import { issueCsrf, validateCsrf } from './csrf.js';
import { writeAudit, recentAudit, verifyAuditChain } from './audit.js';
import {
  listDmsRoleNames,
  listGmsOfficeScopedRoleNames,
  listGmsRoleNames,
  DMS_ROLES_FALLBACK,
} from './client-roles.js';
import {
  listDmsRoles,
  getDmsRolePermissions,
  putDmsRolePermissions,
  getDmsUserOverrides,
  putDmsUserOverrides,
  listDmsMappedGroups,
  getDmsRoleMapping,
  putDmsRoleMapping,
  getDmsUserStatusByEmail,
  DmsInternalApiError,
} from './dms-internal-client.js';
import { GmsInternalApiError, getGmsUserStatus, listGmsOffices } from './gms-internal-client.js';
import { ALL_PERMISSIONS, groupedPermissions } from './dms-permissions.js';

const DMS_RP = 'edams';
// EXECUTIVE included so the standing correspondence-oversight demo role (DMS's
// ROLE_PERMISSIONS.EXECUTIVE, e.g. chief@edams.local in DMS's own demo-user
// seed) is actually selectable/editable here — this list previously omitted
// it even though DMS itself already treats EXECUTIVE as a first-class role.
/** @deprecated Prefer listDmsRoleNames() — kept for callers that need a sync fallback. */
export const DMS_ROLES = [...DMS_ROLES_FALLBACK];

export async function roleCatalog(): Promise<{
  dmsRoles: string[];
  gmsRoles: string[];
  gmsOfficeScopedRoles: string[];
}> {
  const [dmsRoles, gmsRoles, gmsOfficeScopedRoles] = await Promise.all([
    listDmsRoleNames(),
    listGmsRoleNames(),
    listGmsOfficeScopedRoleNames(),
  ]);
  return { dmsRoles, gmsRoles, gmsOfficeScopedRoles };
}

export const APPS = [
  { rp: 'edams', label: 'EDAMS (DMS)' },
  { rp: 'gms', label: 'GMS' },
  { rp: 'mrs', label: 'MRS' },
];

export interface Office { id: number; name: string }

export async function listOffices(): Promise<{ offices: Office[]; error: string | null }> {
  if (!IDP_CONFIG.gms.internalApiKey) {
    return { offices: [], error: 'GMS_INTERNAL_API_KEY is not configured — offices cannot be listed.' };
  }
  try {
    return { offices: await listGmsOffices(), error: null };
  } catch (err) {
    const message = err instanceof GmsInternalApiError ? err.message : 'Could not reach the GMS internal API to list offices.';
    return { offices: [], error: message };
  }
}

/** All values for a cookie name — a stale same-name cookie at another path must
 *  never shadow the live session (see the same helper in portal/router.ts). */
function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) out.push(decodeURIComponent(part.slice(i + 1).trim()));
  }
  return out;
}

declare module 'express-serve-static-core' {
  interface Request {
    adminSession?: PortalSession;
  }
}

async function requireAdmin(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    let session: PortalSession | undefined;
    for (const v of cookieValues(req, 'idp_portal')) {
      session = await getPortalSession(v);
      if (session) break;
    }
    if (!session) { res.redirect('/portal/login'); return; }
    if (!session.groups.includes(IDP_CONFIG.adminGroup)) {
      res.status(403).render('error', { message: 'Admin access required — you are not a member of the admin group.' });
      return;
    }
    req.adminSession = session;
    // Issue the portal's security-CSRF cookie (idp_portal_csrf, path /portal)
    // + matching token so the admin console's "Sign out" can POST to the
    // existing, well-tested /portal/logout (same double-submit scheme as
    // issueSecurityCsrf in portal/router.ts). Uses a distinct locals name so it
    // never shadows the admin forms' own `csrf`.
    const logoutToken = crypto.randomBytes(24).toString('hex');
    // Prefixed with publicBasePath — under /sso this cookie must be scoped to
    // /sso/portal, not a bare /portal, or the browser never sends it back
    // (see the same fix in interactions/csrf.ts and admin/csrf.ts).
    res.cookie('idp_portal_csrf', logoutToken, { httpOnly: true, sameSite: 'lax', secure: IDP_CONFIG.isProd, path: `${IDP_CONFIG.publicBasePath}/portal` });
    res.locals.logoutCsrf = logoutToken;
    next();
  } catch (err) { next(err); }
}

/**
 * Every locally-created user gets one dedicated, auto-managed group — this is
 * what lets the admin UI assign "this user gets role X in DMS, role Y in GMS"
 * directly on the user's own page, with no group DN ever exposed or typed.
 * Shared/AD groups (for assigning many users at once) still work independently
 * via the Groups page and idp_user_groups.
 */
export function personalGroupDn(userId: string): string {
  return `CN=user:${userId},OU=Users,DC=examplecorp,DC=com`;
}

/** Personal groups are auto-managed via System access (above) — never a valid
 *  target for the free-form "add to group" field. */
export function isPersonalGroupDn(dn: string): boolean {
  return dn.startsWith('CN=user:');
}

export interface AccessState {
  dmsRole: string | null;
  dmsError: string | null;
  gmsRole: string | null;
  officeId: number | null;
}

/**
 * email is optional: office assignment is per-user (idp_gms_user_office is keyed
 * by email), so it's only meaningful when called for a specific user. Group-detail
 * calls this without an email and just gets officeId: null back.
 */
export async function getAccess(dn: string, email?: string): Promise<AccessState> {
  let dmsRole: string | null = null;
  let dmsError: string | null = null;
  if (IDP_CONFIG.dmsInternalApiKey) {
    try {
      dmsRole = (await getDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn)).roleName;
    } catch (err) {
      dmsError = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
    }
  } else {
    dmsError = 'DMS_INTERNAL_API_KEY is not configured — set it in .env to manage DMS roles here.';
  }
  const [{ rows: gmsRows }, { rows: officeRows }] = await Promise.all([
    pool.query<{ role_name: string }>('SELECT role_name FROM idp_gms_role_mappings WHERE group_dn = $1', [dn]),
    email
      ? pool.query<{ office_id: number }>('SELECT office_id FROM idp_gms_user_office WHERE email = $1', [email.toLowerCase()])
      : Promise.resolve({ rows: [] as { office_id: number }[] }),
  ]);
  return { dmsRole, dmsError, gmsRole: gmsRows[0]?.role_name ?? null, officeId: officeRows[0]?.office_id ?? null };
}

/**
 * Live, authoritative status of the user INSIDE each app — read straight from the
 * app's own database. The IdP assignment is only the first-sign-in default; after
 * provisioning each app owns its users (roles revoked/granted in DMS or GMS stick,
 * are minted into the next SSO session, and are surfaced here).
 */
// `id` is the app's OWN primary key for this user (DMS's UUID / GMS's bigint,
// stringified) — needed so callers can address DMS's internal permissions API
// by DMS user id without a second lookup query.
export interface LiveAppStatus { exists: boolean; id: string | null; roles: string[]; officeId: number | null; active: boolean | null; error: string | null }

export async function liveDmsStatus(email: string): Promise<LiveAppStatus> {
  const none: LiveAppStatus = { exists: false, id: null, roles: [], officeId: null, active: null, error: null };
  if (!IDP_CONFIG.dmsInternalApiKey) return { ...none, error: 'DMS_INTERNAL_API_KEY is not configured.' };
  try {
    const status = await getDmsUserStatusByEmail(IDP_CONFIG.dmsDefaultTenant, email);
    if (!status.exists) return none;
    return { exists: true, id: status.id, roles: status.roles, officeId: null, active: status.active, error: null };
  } catch (err) {
    const message = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
    return { ...none, error: message };
  }
}

export async function liveGmsStatus(email: string): Promise<LiveAppStatus> {
  const none: LiveAppStatus = { exists: false, id: null, roles: [], officeId: null, active: null, error: null };
  if (!IDP_CONFIG.gms.internalApiKey) return { ...none, error: 'GMS_INTERNAL_API_KEY is not configured.' };
  try {
    const status = await getGmsUserStatus(email);
    if (!status.exists) return none;
    return { exists: true, id: status.id, roles: status.roles, officeId: status.officeId, active: status.active, error: null };
  } catch (err) {
    const message = err instanceof GmsInternalApiError ? err.message : 'Could not reach the GMS internal API.';
    return { ...none, error: message };
  }
}

export interface DmsPermissionsState {
  roleId: string;
  roleDefaults: string[];
  grants: string[];
  revokes: string[];
  effective: Set<string>;
}

/**
 * Resolves the DMS permission-checkbox state for a user: role defaults ∪
 * GRANT overrides − REVOKE overrides. Only meaningful when the user has a DMS
 * role assigned AND already has a DMS user row (dmsUserId, from liveDmsStatus)
 * — before that first DMS sign-in there's no DMS user id for the internal
 * API's user-scoped endpoints to address.
 */
export async function resolveDmsPermissions(dmsRole: string, dmsUserId: string): Promise<DmsPermissionsState> {
  const roles = await listDmsRoles(IDP_CONFIG.dmsDefaultTenant);
  const role = roles.find((r) => r.name === dmsRole);
  if (!role) {
    throw new DmsInternalApiError(
      `DMS role "${dmsRole}" was not found in DMS (tenant "${IDP_CONFIG.dmsDefaultTenant}").`,
      404,
      'ERR-ROLE-NOT-FOUND',
    );
  }
  const [rolePerms, overrides] = await Promise.all([
    getDmsRolePermissions(IDP_CONFIG.dmsDefaultTenant, role.id),
    getDmsUserOverrides(IDP_CONFIG.dmsDefaultTenant, dmsUserId),
  ]);
  const effective = new Set(rolePerms.permissions);
  for (const p of overrides.grants) effective.add(p);
  for (const p of overrides.revokes) effective.delete(p);
  return { roleId: role.id, roleDefaults: rolePerms.permissions, grants: overrides.grants, revokes: overrides.revokes, effective };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Minimal local retry-with-backoff — there is no shared retry/backoff utility
 * elsewhere in this codebase (checked), and applyAccess below is presently the
 * only caller that needs one, so this stays local rather than pulling in a
 * dependency for one call site. Returns whether `fn` eventually succeeded;
 * never throws itself (callers decide how to react to exhaustion).
 */
async function withRetries(fn: () => Promise<void>, attempts: number, baseDelayMs: number): Promise<boolean> {
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await fn();
      return true;
    } catch {
      if (attempt < attempts) await sleep(baseDelayMs * attempt);
    }
  }
  return false;
}

/** Apply (or clear) a user's DMS/GMS role + GMS office in one shot: ensures group
 *  membership, the app entitlement (any role ⇒ entitled), and the app's own role
 *  mapping. officeId is required by GMS for office-scoped roles (validated by caller).
 *  actorEmail/req are the admin making the change — needed here (not just by the
 *  caller's own writeAudit call) so a detected IdP/DMS desync can be logged with an
 *  actor + IP/UA even though it's discovered mid-function, before the caller's normal
 *  audit write runs. */
export async function applyAccess(
  userId: string,
  email: string,
  dn: string,
  dmsRole: string,
  gmsRole: string,
  officeId: number | null,
  actorEmail: string,
  req: Request,
): Promise<void> {
  // FIX: unlike addUserToGroup/removeUserFromGroup (which revoke on every call
  // since each represents one deliberate add/remove), this function is called
  // by a "save the whole access form" endpoint that always submits the FULL
  // current state — including an admin just reviewing and re-saving with no
  // edits. So revocation here must be conditional on something actually
  // changing, not unconditional, or every no-op save would force the user to
  // re-login everywhere. Snapshot current state before any mutation below; if
  // a read fails, treat it as "changed" — under-revoking is the real security
  // gap this closes, a needless revoke on a read hiccup is just an
  // inconvenience.
  let accessChanged = false;
  if (IDP_CONFIG.dmsInternalApiKey) {
    const currentDmsRole = await getDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn)
      .then((m) => m.roleName ?? '')
      .catch(() => null);
    if (currentDmsRole === null || currentDmsRole !== (dmsRole || '')) accessChanged = true;
  }
  {
    const { rows } = await pool.query<{ role_name: string }>('SELECT role_name FROM idp_gms_role_mappings WHERE group_dn = $1', [dn]);
    if ((rows[0]?.role_name ?? '') !== (gmsRole || '')) accessChanged = true;
  }
  {
    const { rows } = await pool.query<{ office_id: number }>('SELECT office_id FROM idp_gms_user_office WHERE email = $1', [email.toLowerCase()]);
    if ((rows[0]?.office_id ?? null) !== officeId) accessChanged = true;
  }

  await pool.query('INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, dn]);

  if (dmsRole && IDP_CONFIG.dmsInternalApiKey) {
    await pool.query('INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [DMS_RP, dn]);
    try {
      await putDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, dmsRole, actorEmail);
    } catch (err) {
      // Two different databases can't share one transaction — compensate by
      // undoing the IdP-side entitlement rather than leaving "entitled to DMS"
      // with no DMS-side role mapping behind it (silently desynced forever).
      // The compensating delete gets its own retries: a bare single attempt
      // would let a transient blip on THIS query, at exactly the wrong moment,
      // turn a recoverable failure into a permanent silent desync.
      const compensated = await withRetries(
        async () => { await pool.query('DELETE FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2', [DMS_RP, dn]); },
        3,
        250,
      );
      if (!compensated) {
        // All compensating-delete retries exhausted: IdP still believes this
        // group is entitled to DMS, the DMS-side role mapping write failed, and
        // we could not undo the IdP-side entitlement either. This is now a
        // confirmed, real desync between IdP and DMS state — it must never
        // vanish into a swallowed catch. Log it as its own audit action,
        // distinct from a normal access change, so it's discoverable via
        // /admin/audit even though it can't be auto-healed from here.
        await writeAudit(req, actorEmail, 'entitlement.desync', dn, {
          relyingParty: DMS_RP,
          dmsRole,
          userId,
          detail:
            'IdP believes this group is entitled to DMS; the DMS-side role mapping write failed and the ' +
            'compensating removal of the IdP-side entitlement failed after 3 attempts. DMS-side state is ' +
            'unknown — reconcile idp_app_entitlements against DMS idp_role_mappings for this group manually.',
          dmsWriteError: (err as Error).message,
        }).catch((auditErr) => {
          logger.error({ err: auditErr }, '[idp:admin] failed to write entitlement.desync audit row');
        });
      }
      throw new Error(`DMS role mapping failed — access change was not applied: ${(err as Error).message}`);
    }
  } else if (IDP_CONFIG.dmsInternalApiKey) {
    await pool.query('DELETE FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2', [DMS_RP, dn]);
    await putDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, null, actorEmail);
  }

  // The GMS-side writes below are all against the IdP's own pool (unlike the DMS
  // writes above, which are unavoidably cross-database) — so unlike those, these
  // CAN and SHOULD be made truly atomic with each other via a real transaction on
  // one held connection, rather than several independent pool.query calls that
  // could each land on a different pooled client and partially apply.
  const normalizedEmail = email.toLowerCase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (gmsRole) {
      await client.query('INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', ['gms', dn]);
      await client.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [dn]);
      await client.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2)', [dn, gmsRole]);
      if (officeId) {
        await client.query(
          `INSERT INTO idp_gms_user_office (email, office_id) VALUES ($1, $2)
           ON CONFLICT (email) DO UPDATE SET office_id = EXCLUDED.office_id`,
          [normalizedEmail, officeId],
        );
      } else {
        await client.query('DELETE FROM idp_gms_user_office WHERE email = $1', [normalizedEmail]);
      }
    } else {
      await client.query('DELETE FROM idp_app_entitlements WHERE relying_party = $1 AND group_dn = $2', ['gms', dn]);
      await client.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [dn]);
      await client.query('DELETE FROM idp_gms_user_office WHERE email = $1', [normalizedEmail]);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  // Same reasoning as addUserToGroup/removeUserFromGroup: this can grant or
  // change an app role, so a real change must invalidate existing sessions —
  // conditioned on accessChanged (computed above) so a no-op re-save doesn't.
  if (accessChanged) {
    await revokeAllSessions(userId, email);
  }
}

/**
 * Add a user to a group (any group, including the admin group), auditing and
 * revoking sessions the same way regardless of caller: the free-text "add to
 * group" form (POST /users/:id/groups) and the "IdP Administrator" checkbox
 * on the Access form (POST /users/:id/access) both need identical behavior
 * here — a distinct audit action for the admin group so granting it is
 * impossible to miss scanning /admin/audit, and an immediate session revoke
 * since group membership can grant admin console access or an app role.
 */
export async function addUserToGroup(userId: string, email: string, groupDn: string, actorEmail: string, req: Request): Promise<void> {
  const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
  await pool.query('INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, groupDn]);
  await writeAudit(req, actorEmail, grantsAdmin ? 'user.admin_group.add' : 'user.group.add', email, { userId, groupDn, grantsAdmin });
  await revokeAllSessions(userId, email);
}

/** Remove a user from a group — mirrors addUserToGroup above, same distinct
 *  admin-group audit action name and session revoke on the way out. */
export async function removeUserFromGroup(userId: string, email: string, groupDn: string, actorEmail: string, req: Request): Promise<void> {
  const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
  await pool.query('DELETE FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2', [userId, groupDn]);
  await writeAudit(req, actorEmail, grantsAdmin ? 'user.admin_group.remove' : 'user.group.remove', email, { userId, groupDn });
  await revokeAllSessions(userId, email);
}

/**
 * Revoke sessions for every current member of a group — the group-wide
 * counterpart to addUserToGroup/removeUserFromGroup/applyAccess above, used
 * after a group-level access change (entitlements, GMS role) since that
 * changes what every member of the group can reach, not just one user.
 * Best-effort per member: one member's revoke failing (e.g. a transient GMS
 * bridge hiccup, already swallowed inside revokeAllSessions itself) must not
 * stop the rest of the group from being revoked.
 */
async function revokeSessionsForGroupMembers(dn: string): Promise<void> {
  const { rows } = await pool.query<{ id: string; email: string }>(
    'SELECT u.id, u.email FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id WHERE g.group_dn = $1',
    [dn],
  );
  for (const row of rows) {
    await revokeAllSessions(row.id, row.email).catch((err) => {
      logger.error({ err, userId: row.id, email: row.email, dn }, '[idp:admin] group-wide session revoke failed for member');
    });
  }
}

export async function allGroupDns(): Promise<string[]> {
  const { rows } = await pool.query<{ group_dn: string }>(`
    SELECT group_dn FROM idp_user_groups
    UNION SELECT group_dn FROM idp_app_entitlements
    UNION SELECT group_dn FROM idp_gms_role_mappings
  `);
  const set = new Set(rows.map((r) => r.group_dn));
  if (IDP_CONFIG.dmsInternalApiKey) {
    try {
      (await listDmsMappedGroups(IDP_CONFIG.dmsDefaultTenant)).forEach((dn) => set.add(dn));
    } catch {
      // DMS unreachable — still show what the IdP itself knows about.
    }
  }
  return [...set].sort();
}

/**
 * Groups a user may be added to via the free-text field on their page. Was
 * unvalidated: any admin could type the literal admin-group DN (silent backdoor
 * admin) or another user's personal group DN (cloning their DMS/GMS role).
 * Constrained to groups the system already knows about — plus the admin group
 * itself, since granting IdP Administration access is legitimate, just no
 * longer silent (see the distinct audit action below) — never a personal DN.
 */
export async function addableGroupDns(): Promise<Set<string>> {
  const dns = (await allGroupDns()).filter((dn) => !isPersonalGroupDn(dn));
  return new Set([...dns, IDP_CONFIG.adminGroup]);
}

export function adminRouter(provider: Provider): Router {
  const router = Router();
  router.use(express.urlencoded({ extended: false }));
  router.use(requireAdmin);
  router.use((req, res, next) => { res.set('cache-control', 'no-store'); res.locals.currentPath = req.baseUrl + (req.path === '/' ? '' : req.path); next(); });

  // ── Dashboard ───────────────────────────────────────────────────────────
  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const [{ rows: userCountRows }, groupList, { rows: statRows }, { rows: alertRows }] = await Promise.all([
        pool.query<{ count: string }>('SELECT COUNT(*) FROM idp_users'),
        allGroupDns(),
        pool.query<{ sso: string; portal: string; fails: string; audits: string }>(
          `SELECT
             (SELECT COUNT(*) FROM oidc_artifacts WHERE kind = 'Session' AND payload->>'accountId' IS NOT NULL AND (expires_at IS NULL OR expires_at > NOW())) AS sso,
             (SELECT COUNT(*) FROM idp_web_sessions WHERE kind = 'portal' AND expires_at > NOW()) AS portal,
             (SELECT COUNT(*) FROM idp_login_events WHERE success = FALSE AND created_at > NOW() - INTERVAL '24 hours') AS fails,
             (SELECT COUNT(*) FROM idp_admin_audit WHERE created_at > NOW() - INTERVAL '7 days') AS audits`,
        ),
        pool.query<{ email: string; failures: string }>(
          `SELECT email, COUNT(*) AS failures FROM idp_login_events
           WHERE success = FALSE AND created_at > NOW() - INTERVAL '15 minutes'
           GROUP BY email HAVING COUNT(*) >= 5 ORDER BY failures DESC LIMIT 5`,
        ),
      ]);
      res.render('admin/dashboard', {
        adminEmail: req.adminSession!.email,
        userCount: userCountRows[0].count,
        groupCount: groupList.length,
        dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
        stats: statRows[0],
        alerts: alertRows,
      });
    } catch (err) { next(err); }
  });

  // ── Users ───────────────────────────────────────────────────────────────
  router.get('/users', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const q = String(req.query.q ?? '').trim();
      const PAGE_SIZE = 20;
      const page = Math.max(1, Number(req.query.page) || 1);
      const [{ rows }, { rows: countRows }] = await Promise.all([
        pool.query(
          `SELECT u.id, u.email, u.given_name, u.family_name, u.is_active, u.source, u.last_login_at,
                  (SELECT COUNT(*) FROM idp_user_groups g WHERE g.user_id = u.id) AS group_count
           FROM idp_users u
           WHERE ($1 = '' OR u.email ILIKE '%' || $1 || '%')
           ORDER BY u.email
           LIMIT $2 OFFSET $3`,
          [q, PAGE_SIZE, (page - 1) * PAGE_SIZE],
        ),
        pool.query<{ count: string }>(
          `SELECT COUNT(*) FROM idp_users u WHERE ($1 = '' OR u.email ILIKE '%' || $1 || '%')`,
          [q],
        ),
      ]);
      const total = Number(countRows[0].count);
      res.render('admin/users', {
        users: rows,
        q,
        page,
        totalPages: Math.max(1, Math.ceil(total / PAGE_SIZE)),
        total,
        adminEmail: req.adminSession!.email,
      });
    } catch (err) { next(err); }
  });

  router.get('/users/new', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const [{ offices, error: officesError }, catalog] = await Promise.all([listOffices(), roleCatalog()]);
      res.render('admin/user-new', {
        csrf: issueCsrf(res, IDP_CONFIG.isProd),
        error: null,
        adminEmail: req.adminSession!.email,
        dmsRoles: catalog.dmsRoles,
        gmsRoles: catalog.gmsRoles,
        gmsOfficeScopedRoles: catalog.gmsOfficeScopedRoles,
        dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
        offices,
        officesError,
        form: { email: '', given_name: '', family_name: '', dms_role: '', gms_role: '', office_id: '' },
      });
    } catch (err) { next(err); }
  });

  router.post('/users', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const catalog = await roleCatalog();
      const email = String(req.body.email ?? '').trim().toLowerCase();
      const givenName = String(req.body.given_name ?? '').trim();
      const familyName = String(req.body.family_name ?? '').trim();
      const password = String(req.body.password ?? '');
      const dmsRole = catalog.dmsRoles.includes(String(req.body.dms_role ?? '')) ? String(req.body.dms_role) : '';
      const gmsRole = catalog.gmsRoles.includes(String(req.body.gms_role ?? '')) ? String(req.body.gms_role) : '';
      const officeId = req.body.office_id ? Number(req.body.office_id) : null;

      const rerender = async (error: string) => {
        const { offices, error: officesError } = await listOffices();
        res.render('admin/user-new', {
          csrf: issueCsrf(res, IDP_CONFIG.isProd),
          error,
          adminEmail: req.adminSession!.email,
          dmsRoles: catalog.dmsRoles,
          gmsRoles: catalog.gmsRoles,
          gmsOfficeScopedRoles: catalog.gmsOfficeScopedRoles,
          dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
          offices,
          officesError,
          form: { email, given_name: givenName, family_name: familyName, dms_role: dmsRole, gms_role: gmsRole, office_id: req.body.office_id ?? '' },
        });
      };

      if (!email || !password || password.length < 8) { await rerender('Email and an 8+ character password are required.'); return; }
      if (catalog.gmsOfficeScopedRoles.includes(gmsRole) && !officeId) {
        await rerender(`GMS role "${gmsRole}" requires an office — pick one below.`);
        return;
      }

      const pwd = await hashPassword(password);
      const { rows } = await pool.query<{ id: string }>(
        `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active)
         VALUES ($1, TRUE, $2, $3, $4, 'local', TRUE)
         RETURNING id`,
        [email, givenName, familyName, pwd],
      );
      const userId = rows[0].id;
      if (dmsRole || gmsRole) {
        await applyAccess(userId, email, personalGroupDn(userId), dmsRole, gmsRole, officeId, req.adminSession!.email, req);
      }
      await writeAudit(req, req.adminSession!.email, 'user.create', email, { userId, dmsRole, gmsRole, officeId });
      res.redirect(`/admin/users/${userId}`);
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === '23505') {
        const [{ offices, error: officesError }, catalog] = await Promise.all([listOffices(), roleCatalog()]);
        res.render('admin/user-new', {
          csrf: issueCsrf(res, IDP_CONFIG.isProd),
          error: 'A user with that email already exists.',
          adminEmail: req.adminSession!.email,
          dmsRoles: catalog.dmsRoles,
          gmsRoles: catalog.gmsRoles,
          gmsOfficeScopedRoles: catalog.gmsOfficeScopedRoles,
          dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
          offices,
          officesError,
          form: {
            email: String(req.body.email ?? ''),
            given_name: String(req.body.given_name ?? ''),
            family_name: String(req.body.family_name ?? ''),
            dms_role: String(req.body.dms_role ?? ''),
            gms_role: String(req.body.gms_role ?? ''),
            office_id: req.body.office_id ?? '',
          },
        });
        return;
      }
      next(err);
    }
  });

  router.get('/users/:id', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Explicit column list — `SELECT *` was passing password_hash and the raw
      // totp_secret into the render locals; the template happens not to read
      // them today, but they sat in scope for the next template edit or debug dump.
      const { rows: userRows } = await pool.query(
        `SELECT id, email, email_verified, given_name, family_name, is_active, source,
                must_change_password, totp_enabled, failed_logins, locked_until,
                last_login_at, created_at, updated_at
         FROM idp_users WHERE id = $1`,
        [req.params.id],
      );
      const user = userRows[0];
      if (!user) { res.status(404).render('error', { message: 'User not found.' }); return; }
      const personalDn = personalGroupDn(user.id);
      const [{ rows: groups }, knownGroups, access, officesResult, liveDms, liveGms, { rows: history }, catalog] = await Promise.all([
        pool.query<{ group_dn: string }>('SELECT group_dn FROM idp_user_groups WHERE user_id = $1 ORDER BY group_dn', [user.id]),
        allGroupDns(),
        getAccess(personalDn, user.email),
        listOffices(),
        liveDmsStatus(user.email),
        liveGmsStatus(user.email),
        pool.query(
          `SELECT actor_email, action, detail, created_at FROM idp_admin_audit
           WHERE target = $1 OR detail->>'userId' = $2
           ORDER BY id DESC LIMIT 20`,
          [user.email, user.id],
        ),
        roleCatalog(),
      ]);

      // Whether this user is already a member of the admin group — backs the
      // "IdP Administrator" checkbox folded into the Access form below.
      const isAdmin = groups.some((g) => g.group_dn === IDP_CONFIG.adminGroup);

      // Per-user DMS permission customization: only resolvable once the user
      // has a DMS role assigned AND already has a DMS user row (liveDms.id) —
      // mirrors the same "not provisioned yet" gate the live-status table above
      // already uses for DMS/GMS.
      let dmsPermissions: DmsPermissionsState | null = null;
      let dmsPermissionsError: string | null = null;
      if (access.dmsRole && liveDms.exists && liveDms.id) {
        try {
          dmsPermissions = await resolveDmsPermissions(access.dmsRole, liveDms.id);
        } catch (err) {
          dmsPermissionsError = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
        }
      }

      res.render('admin/user-detail', {
        liveDms,
        liveGms,
        history,
        user,
        isAdmin,
        dmsPermissions,
        dmsPermissionsError,
        dmsPermissionGroups: groupedPermissions(),
        // The personal access group is managed entirely through the dropdowns below —
        // hide it from the raw "other groups" list so it doesn't read as a stray group.
        groups: groups.map((g) => g.group_dn).filter((dn) => dn !== personalDn),
        // Never suggest ANY personal group (not just this user's own) — typing
        // another user's personal DN here would clone their DMS/GMS role.
        knownGroups: [...new Set([...knownGroups, IDP_CONFIG.adminGroup])].filter((dn) => !isPersonalGroupDn(dn)).sort(),
        access,
        dmsRoles: catalog.dmsRoles,
        gmsRoles: catalog.gmsRoles,
        gmsOfficeScopedRoles: catalog.gmsOfficeScopedRoles,
        dmsConnected: Boolean(IDP_CONFIG.dmsInternalApiKey),
        offices: officesResult.offices,
        officesError: officesResult.error,
        csrf: issueCsrf(res, IDP_CONFIG.isProd),
        adminEmail: req.adminSession!.email,
      });
    } catch (err) { next(err); }
  });

  router.post('/users/:id/access', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      // Separation of duties: membership in the admin group is the ONLY gate on
      // this whole console, so without this check an admin could grant
      // themselves SYSTEM_ADMIN in DMS or super_admin in GMS unilaterally.
      if (userId === req.adminSession!.accountId) {
        res.status(403).render('error', { message: 'You cannot change your own DMS/GMS access — ask another admin to make this change.' });
        return;
      }
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { res.status(404).render('error', { message: 'User not found.' }); return; }

      const catalog = await roleCatalog();
      const dmsRole = catalog.dmsRoles.includes(String(req.body.dms_role ?? '')) ? String(req.body.dms_role) : '';
      const gmsRole = catalog.gmsRoles.includes(String(req.body.gms_role ?? '')) ? String(req.body.gms_role) : '';
      const officeId = req.body.office_id ? Number(req.body.office_id) : null;

      if (catalog.gmsOfficeScopedRoles.includes(gmsRole) && !officeId) {
        res.status(400).render('error', { message: `GMS role "${gmsRole}" requires an office to be selected — go back and pick one.` });
        return;
      }

      await applyAccess(userId, rows[0].email, personalGroupDn(userId), dmsRole, gmsRole, officeId, req.adminSession!.email, req);
      await writeAudit(req, req.adminSession!.email, 'user.access', rows[0].email, { userId, dmsRole, gmsRole, officeId });

      // "IdP Administrator" checkbox, folded into this same form so granting
      // admin-console access no longer requires the free-text "add to group"
      // field with the literal admin-group DN. Reuses the exact
      // add/removeUserFromGroup helpers the free-text group form itself uses
      // (same audit action names, same session revoke) — only fires on an
      // actual state change, so toggling other fields on this form without
      // touching the checkbox doesn't spuriously re-audit/re-revoke.
      const wantsAdmin = req.body.is_admin === 'on' || req.body.is_admin === 'true';
      const { rows: adminMembership } = await pool.query(
        'SELECT 1 FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2',
        [userId, IDP_CONFIG.adminGroup],
      );
      const isCurrentlyAdmin = adminMembership.length > 0;
      if (wantsAdmin && !isCurrentlyAdmin) {
        await addUserToGroup(userId, rows[0].email, IDP_CONFIG.adminGroup, req.adminSession!.email, req);
      } else if (!wantsAdmin && isCurrentlyAdmin) {
        await removeUserFromGroup(userId, rows[0].email, IDP_CONFIG.adminGroup, req.adminSession!.email, req);
      }

      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  // Per-user DMS permission customization — writes ONLY via DMS's internal
  // API (dms-internal-client.ts), never direct SQL from SSO, so DMS's own
  // privilege-escalation checks/audit logging/session revocation still run.
  router.post('/users/:id/dms-permissions', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      // Same separation-of-duties rule as /access: this panel can grant this
      // user extra DMS permissions beyond their role, so self-service on your
      // own account is blocked here too.
      if (userId === req.adminSession!.accountId) {
        res.status(403).render('error', { message: 'You cannot change your own DMS permissions — ask another admin to make this change.' });
        return;
      }
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { res.status(404).render('error', { message: 'User not found.' }); return; }
      const email = rows[0].email;

      const access = await getAccess(personalGroupDn(userId), email);
      if (!access.dmsRole) {
        res.status(400).render('error', { message: 'This user has no DMS role — set one under "Initial system access" first.' });
        return;
      }
      const liveDms = await liveDmsStatus(email);
      if (!liveDms.exists || !liveDms.id) {
        res.status(400).render('error', { message: 'This user does not exist in DMS yet — permissions can only be customized after their first DMS sign-in provisions them.' });
        return;
      }

      let state: DmsPermissionsState;
      try {
        state = await resolveDmsPermissions(access.dmsRole, liveDms.id);
      } catch (err) {
        const message = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
        res.status(err instanceof DmsInternalApiError ? err.status : 503).render('error', { message });
        return;
      }

      // Defense in depth: only ever send permission strings this IdP itself
      // knows about, even though the form only renders known checkboxes.
      const validPermissions = new Set(ALL_PERMISSIONS);
      const checked = new Set(
        ([] as string[]).concat(req.body.permissions ?? []).filter((p) => validPermissions.has(p)),
      );
      const roleDefaults = new Set(state.roleDefaults);
      const grants = [...checked].filter((p) => !roleDefaults.has(p));
      const revokes = [...roleDefaults].filter((p) => !checked.has(p));

      try {
        const overrides = await putDmsUserOverrides(IDP_CONFIG.dmsDefaultTenant, liveDms.id, grants, revokes, req.adminSession!.email);
        await writeAudit(req, req.adminSession!.email, 'user.dms_permissions', email, {
          userId,
          dmsUserId: liveDms.id,
          dmsRole: access.dmsRole,
          grants: overrides.grants,
          revokes: overrides.revokes,
        });
      } catch (err) {
        const message = err instanceof DmsInternalApiError ? `DMS rejected the permission update: ${err.message}` : 'Could not reach the DMS internal API.';
        res.status(err instanceof DmsInternalApiError ? err.status : 503).render('error', { message });
        return;
      }

      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  router.post('/users/:id/toggle-active', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      const { rows } = await pool.query<{ email: string; is_active: boolean }>(
        'UPDATE idp_users SET is_active = NOT is_active, updated_at = NOW() WHERE id = $1 RETURNING email, is_active',
        [userId],
      );
      if (rows[0]) {
        // Disabling revokes every live session everywhere (SSO, portal, gateway,
        // GMS) — the account goes dark immediately, not at next login.
        const revoked = rows[0].is_active ? null : await revokeAllSessions(userId, rows[0].email);
        await writeAudit(
          req,
          req.adminSession!.email,
          rows[0].is_active ? 'user.enable' : 'user.disable',
          rows[0].email,
          revoked ? { userId, revoked } : { userId },
        );
      }
      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  // Admin password reset: sets a temporary password the user MUST change at
  // next sign-in, and revokes all live sessions (a reset usually means the old
  // credential can no longer be trusted).
  router.post('/users/:id/reset-password', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      const password = String(req.body.password ?? '');
      if (password.length < 8) {
        res.status(400).render('error', { message: 'Temporary password must be at least 8 characters — go back and try again.' });
        return;
      }
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { res.status(404).render('error', { message: 'User not found.' }); return; }

      await pool.query(
        `UPDATE idp_users
         SET password_hash = $2, must_change_password = TRUE, failed_logins = 0, locked_until = NULL, updated_at = NOW()
         WHERE id = $1`,
        [userId, await hashPassword(password)],
      );
      const revoked = await revokeAllSessions(userId, rows[0].email);
      await writeAudit(req, req.adminSession!.email, 'user.password_reset', rows[0].email, { userId, revoked });
      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  router.post('/users/:id/groups', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      const groupDn = String(req.body.group_dn ?? '').trim();
      if (groupDn) {
        const grantsAdmin = groupDn === IDP_CONFIG.adminGroup;
        const allowed = await addableGroupDns();
        if (!allowed.has(groupDn)) {
          res.status(400).render('error', { message: 'Not a recognized group — configure its access on the Groups page first, or pick one from the list.' });
          return;
        }
        // Separation of duties: /access blocks all self-service on your own
        // account. This route grants entitlements too (admin-group membership,
        // or any group mapped to a DMS/GMS role), so it must enforce the same
        // rule — otherwise an admin could self-add to a non-admin group that
        // carries super_admin/SYSTEM_ADMIN and mint that role on next SSO login.
        if (userId === req.adminSession!.accountId) {
          const groupAccess = await getAccess(groupDn);
          const grantsAppRole = Boolean(groupAccess.dmsRole || groupAccess.gmsRole);
          if (grantsAdmin || grantsAppRole) {
            res.status(403).render('error', { message: 'You cannot grant yourself elevated access — ask another admin.' });
            return;
          }
        }
        const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
        if (!rows[0]) { res.status(404).render('error', { message: 'User not found.' }); return; }

        await addUserToGroup(userId, rows[0].email, groupDn, req.adminSession!.email, req);
      }
      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  router.post('/users/:id/groups/remove', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      const groupDn = String(req.body.group_dn ?? '');
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { res.status(404).render('error', { message: 'User not found.' }); return; }

      await removeUserFromGroup(userId, rows[0].email, groupDn, req.adminSession!.email, req);
      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  // ── Groups (entitlements + per-app roles) ──────────────────────────────
  router.get('/groups', async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Per-user personal groups are managed from the user's own page (System
      // access), not listed here — this page is for shared/AD groups only.
      const dns = (await allGroupDns()).filter((dn) => !dn.startsWith('CN=user:'));
      const { rows: memberCounts } = await pool.query<{ group_dn: string; count: string }>(
        'SELECT group_dn, COUNT(*) AS count FROM idp_user_groups GROUP BY group_dn',
      );
      const countByDn = new Map(memberCounts.map((r) => [r.group_dn, r.count]));
      res.render('admin/groups', {
        groups: dns.map((dn) => ({ dn, memberCount: countByDn.get(dn) ?? '0' })),
        adminEmail: req.adminSession!.email,
      });
    } catch (err) { next(err); }
  });

  router.get('/groups/detail', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const dn = String(req.query.dn ?? '');
      if (!dn) { res.redirect('/admin/groups'); return; }

      const [{ rows: members }, { rows: entRows }, accessState, catalog] = await Promise.all([
        pool.query<{ id: string; email: string }>(
          'SELECT u.id, u.email FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id WHERE g.group_dn = $1 ORDER BY u.email',
          [dn],
        ),
        pool.query<{ relying_party: string }>('SELECT relying_party FROM idp_app_entitlements WHERE group_dn = $1', [dn]),
        getAccess(dn),
        roleCatalog(),
      ]);

      res.render('admin/group-detail', {
        dn,
        members,
        entitled: new Set(entRows.map((r) => r.relying_party)),
        apps: APPS,
        dmsRole: accessState.dmsRole,
        dmsError: accessState.dmsError,
        dmsRoles: catalog.dmsRoles,
        gmsRole: accessState.gmsRole,
        gmsRoles: catalog.gmsRoles,
        csrf: issueCsrf(res, IDP_CONFIG.isProd),
        adminEmail: req.adminSession!.email,
      });
    } catch (err) { next(err); }
  });

  router.post('/groups/entitlements', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const dn = String(req.body.dn ?? '');
      const selected = ([] as string[]).concat(req.body.rp ?? []).filter((rp) => APPS.some((a) => a.rp === rp));

      const { rows: currentRows } = await pool.query<{ relying_party: string }>(
        'SELECT relying_party FROM idp_app_entitlements WHERE group_dn = $1',
        [dn],
      );
      const currentSet = new Set(currentRows.map((r) => r.relying_party));
      const nextSet = new Set(selected);
      const entitlementsChanged = currentSet.size !== nextSet.size || [...currentSet].some((rp) => !nextSet.has(rp));

      await pool.query('DELETE FROM idp_app_entitlements WHERE group_dn = $1', [dn]);
      for (const rp of selected) {
        await pool.query('INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2)', [rp, dn]);
      }
      await writeAudit(req, req.adminSession!.email, 'group.entitlements', dn, { apps: selected });
      // Entitlements gate which apps this group's members can reach — a real
      // change must invalidate their existing sessions (same reasoning as
      // applyAccess()/addUserToGroup), conditioned on an actual diff so a
      // no-op re-save of the same checkboxes doesn't log anyone out.
      if (entitlementsChanged) {
        await revokeSessionsForGroupMembers(dn);
      }
      res.redirect(`/admin/groups/detail?dn=${encodeURIComponent(dn)}`);
    } catch (err) { next(err); }
  });

  router.post('/groups/dms-role', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const dn = String(req.body.dn ?? '');
      const role = String(req.body.role ?? '');
      if (!IDP_CONFIG.dmsInternalApiKey) { res.status(503).render('error', { message: 'DMS_INTERNAL_API_KEY is not configured.' }); return; }

      const currentDmsRole = await getDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn)
        .then((m) => m.roleName ?? '')
        .catch(() => null);
      const dmsRoleChanged = currentDmsRole === null || currentDmsRole !== (role || '');

      await putDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, role || null, req.adminSession!.email);
      await writeAudit(req, req.adminSession!.email, 'group.dms_role', dn, { role: role || null });
      // DMS only re-derives a user's role set at their next OIDC login (DMS's
      // /auth/refresh recomputes permissions from the roles already baked
      // into the refresh token, not from idp_role_mappings — confirmed in
      // DMS/backend/src/modules/auth/auth.routes.ts). Without a forced
      // revoke, a member already logged into DMS keeps their old DMS role
      // for the rest of their refresh-token lifetime after this changes.
      // revokeSessionsForGroupMembers already calls DMS's existing, already
      // battle-tested /auth/backchannel-logout receiver per member (via
      // notifyDmsLogout inside revokeAllSessions) — no DMS-side change
      // needed, this just makes sure that path gets triggered here too.
      // Same null-means-changed fail-safe as applyAccess(): if the current
      // mapping can't be read, assume it changed rather than silently skip.
      if (dmsRoleChanged) {
        await revokeSessionsForGroupMembers(dn);
      }
      res.redirect(`/admin/groups/detail?dn=${encodeURIComponent(dn)}`);
    } catch (err) { next(err); }
  });

  router.post('/groups/gms-role', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const dn = String(req.body.dn ?? '');
      const role = String(req.body.role ?? '');

      const { rows: currentRows } = await pool.query<{ role_name: string }>(
        'SELECT role_name FROM idp_gms_role_mappings WHERE group_dn = $1',
        [dn],
      );
      const gmsRoleChanged = (currentRows[0]?.role_name ?? '') !== role;

      await pool.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [dn]);
      if (role) {
        await pool.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2) ON CONFLICT DO NOTHING', [dn, role]);
      }
      await writeAudit(req, req.adminSession!.email, 'group.gms_role', dn, { role: role || null });
      // Same reasoning as the entitlements handler above: a real GMS-role
      // change for this group must invalidate its members' sessions, gated
      // on an actual diff.
      if (gmsRoleChanged) {
        await revokeSessionsForGroupMembers(dn);
      }
      res.redirect(`/admin/groups/detail?dn=${encodeURIComponent(dn)}`);
    } catch (err) { next(err); }
  });

  // ── DMS role permission editor ─────────────────────────────────────────
  // Per-ROLE default permissions (DMS's role_permissions table) — distinct
  // from the per-USER override panel on /users/:id above. Same rule applies:
  // writes ONLY via DMS's internal API, never direct SQL from SSO.
  router.get('/dms-roles', async (req: Request, res: Response, next: NextFunction) => {
    try {
      let roles: Awaited<ReturnType<typeof listDmsRoles>> = [];
      let error: string | null = null;
      try {
        roles = await listDmsRoles(IDP_CONFIG.dmsDefaultTenant);
      } catch (err) {
        error = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
      }
      res.render('admin/dms-roles', { roles, error, tenant: IDP_CONFIG.dmsDefaultTenant, adminEmail: req.adminSession!.email });
    } catch (err) { next(err); }
  });

  router.get('/dms-roles/detail', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const roleId = String(req.query.roleId ?? '');
      if (!roleId) { res.redirect('/admin/dms-roles'); return; }
      let roleName = '';
      let checked = new Set<string>();
      let error: string | null = null;
      try {
        const result = await getDmsRolePermissions(IDP_CONFIG.dmsDefaultTenant, roleId);
        roleName = result.roleName;
        checked = new Set(result.permissions);
      } catch (err) {
        error = err instanceof DmsInternalApiError ? err.message : 'Could not reach the DMS internal API.';
      }
      res.render('admin/dms-role-detail', {
        roleId,
        roleName,
        error,
        checked,
        groups: groupedPermissions(),
        tenant: IDP_CONFIG.dmsDefaultTenant,
        csrf: issueCsrf(res, IDP_CONFIG.isProd),
        adminEmail: req.adminSession!.email,
      });
    } catch (err) { next(err); }
  });

  router.post('/dms-roles/detail', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const roleId = String(req.body.roleId ?? '');
      if (!roleId) { res.redirect('/admin/dms-roles'); return; }
      const validPermissions = new Set(ALL_PERMISSIONS);
      const selected = ([] as string[]).concat(req.body.permissions ?? []).filter((p) => validPermissions.has(p));
      try {
        await putDmsRolePermissions(IDP_CONFIG.dmsDefaultTenant, roleId, selected, req.adminSession!.email);
      } catch (err) {
        const message = err instanceof DmsInternalApiError ? `DMS rejected the permission update: ${err.message}` : 'Could not reach the DMS internal API.';
        res.status(err instanceof DmsInternalApiError ? err.status : 503).render('error', { message });
        return;
      }
      await writeAudit(req, req.adminSession!.email, 'dms_role.permissions', roleId, { roleId, permissions: selected });
      res.redirect(`/admin/dms-roles/detail?roleId=${encodeURIComponent(roleId)}`);
    } catch (err) { next(err); }
  });

  // ── OIDC clients (relying parties) ─────────────────────────────────────
  // Read-only. oidc-provider v8 loads `clients` as a static in-memory list at
  // boot (oidc/provider.ts → oidc/clients.ts's loadClients()) and its
  // Client.find() caches statically-configured clients forever with no
  // supported reload hook (unlike signing keys — see jwks.ts's
  // reloadProviderKeys, which re-runs oidc-provider's own idempotent keystore
  // initializer). A write here could therefore update idp_clients without
  // ever taking effect on the running process until a restart; a button that
  // looks like it disables a client live but silently doesn't would be worse
  // than no button. This page exists so admins/auditors can at least see
  // every registered relying party (GMS/EDAMS/etc.) in one place —
  // client_secret is intentionally never selected or rendered.
  router.get('/clients', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { rows } = await pool.query<{
        client_id: string;
        name: string;
        redirect_uris: string[];
        post_logout_redirect_uris: string[];
        grant_types: string[];
        is_active: boolean;
        created_at: string;
        updated_at: string;
      }>(
        `SELECT client_id, name, redirect_uris, post_logout_redirect_uris, grant_types, is_active, created_at, updated_at
         FROM idp_clients ORDER BY name`,
      );
      res.render('admin/clients', { clients: rows, adminEmail: req.adminSession!.email });
    } catch (err) { next(err); }
  });

  // ── Audit trail ─────────────────────────────────────────────────────────
  router.get('/audit', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const entries = await recentAudit(100);
      res.render('admin/audit', { entries, chainResult: null, adminEmail: req.adminSession!.email });
    } catch (err) { next(err); }
  });

  // Walks the whole idp_admin_audit hash chain and recomputes every non-legacy
  // row's HMAC — surfaces tampering (see src/admin/audit.ts's verifyAuditChain).
  // GET (not POST/CSRF-gated) since it's read-only and side-effect-free.
  router.get('/audit/verify', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const [entries, chainResult] = await Promise.all([recentAudit(100), verifyAuditChain()]);
      res.render('admin/audit', { entries, chainResult, adminEmail: req.adminSession!.email });
    } catch (err) { next(err); }
  });

  // ── MFA reset (lost device) ─────────────────────────────────────────────
  router.post('/users/:id/mfa-reset', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const userId = String(req.params.id);
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [userId]);
      if (!rows[0]) { res.status(404).render('error', { message: 'User not found.' }); return; }
      await disableTotp(userId);
      await writeAudit(req, req.adminSession!.email, 'user.mfa_reset', rows[0].email, { userId });
      res.redirect(`/admin/users/${userId}`);
    } catch (err) { next(err); }
  });

  // ── Signing keys (JWKS rotation) ────────────────────────────────────────
  router.get('/keys', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const keys = await listSigningKeys();
      res.render('admin/keys', { keys, csrf: issueCsrf(res, IDP_CONFIG.isProd), adminEmail: req.adminSession!.email });
    } catch (err) { next(err); }
  });

  router.post('/keys/rotate', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const jwk = await generateSigningKey();
      await reloadProviderKeys(provider);
      await writeAudit(req, req.adminSession!.email, 'keys.rotate', jwk.kid, {});
      res.redirect('/admin/keys');
    } catch (err) { next(err); }
  });

  router.post('/keys/retire', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const kid = String(req.body.kid ?? '');
      const result = await retireSigningKey(kid);
      if (!result.ok) { res.status(400).render('error', { message: result.error ?? 'Retire failed.' }); return; }
      await reloadProviderKeys(provider);
      await writeAudit(req, req.adminSession!.email, 'keys.retire', kid, {});
      res.redirect('/admin/keys');
    } catch (err) { next(err); }
  });

  // ── Session inspector ───────────────────────────────────────────────────
  router.get('/sessions', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const [{ rows: webSessions }, { rows: ssoSessions }] = await Promise.all([
        pool.query(
          `SELECT kind, key, payload->>'email' AS email, created_at, expires_at
           FROM idp_web_sessions WHERE kind IN ('portal', 'gateway') AND expires_at > NOW()
           ORDER BY created_at DESC LIMIT 200`,
        ),
        pool.query(
          `SELECT a.id AS key, u.email, a.created_at, a.expires_at
           FROM oidc_artifacts a LEFT JOIN idp_users u ON u.id::text = a.payload->>'accountId'
           WHERE a.kind = 'Session' AND a.payload->>'accountId' IS NOT NULL
             AND (a.expires_at IS NULL OR a.expires_at > NOW())
           ORDER BY a.created_at DESC LIMIT 200`,
        ),
      ]);
      res.render('admin/sessions', {
        webSessions,
        ssoSessions,
        csrf: issueCsrf(res, IDP_CONFIG.isProd),
        adminEmail: req.adminSession!.email,
      });
    } catch (err) { next(err); }
  });

  router.post('/sessions/kill', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const kind = String(req.body.kind ?? '');
      const key = String(req.body.key ?? '');
      // Look up whose session this is BEFORE deleting it — the audit row used to
      // record only `{kind}:{key-prefix}`, with no way afterward to reconstruct
      // whose session was ended or when relative to anything else on that account.
      let email: string | null = null;
      let accountId: string | null = null;
      if (kind === 'sso') {
        const { rows } = await pool.query<{ email: string | null; account_id: string | null }>(
          `SELECT u.email, a.payload->>'accountId' AS account_id
           FROM oidc_artifacts a LEFT JOIN idp_users u ON u.id::text = a.payload->>'accountId'
           WHERE a.kind = 'Session' AND a.id = $1`,
          [key],
        );
        email = rows[0]?.email ?? null;
        accountId = rows[0]?.account_id ?? null;
      } else if (kind === 'portal' || kind === 'gateway') {
        const { rows } = await pool.query<{ email: string | null; account_id: string | null }>(
          `SELECT payload->>'email' AS email, payload->>'accountId' AS account_id FROM idp_web_sessions WHERE kind = $1 AND key = $2`,
          [kind, key],
        );
        email = rows[0]?.email ?? null;
        accountId = rows[0]?.account_id ?? null;
      }
      if (!accountId && email) {
        const { rows } = await pool.query<{ id: string }>('SELECT id FROM idp_users WHERE email = $1', [email.toLowerCase()]);
        accountId = rows[0]?.id ?? null;
      }

      // Platform audit finding 4.5: this used to only delete the single
      // oidc_artifacts/idp_web_sessions row named by kind+key, leaving that
      // account's AccessToken/RefreshToken/Grant rows — and any GMS bridge
      // session — completely untouched. Since the account's refresh token
      // still worked, a "killed" session could keep silently renewing
      // itself for a full day or more, and a bridged GMS login wasn't
      // touched at all. There's no narrower revoke primitive in this
      // codebase (tokens/grants are tracked per-account, not per-session),
      // so this now reuses the exact same account-wide revokeAllSessions
      // the working "sign out everywhere" button already calls, scoped to
      // whichever account this one session belongs to.
      const revoked = accountId && email ? await revokeAllSessions(accountId, email) : null;
      if (!revoked) {
        // Couldn't resolve an account (e.g. the row vanished between page
        // render and this click) — fall back to deleting just the one row
        // so the button still does something rather than silently no-op.
        if (kind === 'sso') {
          await pool.query(`DELETE FROM oidc_artifacts WHERE kind = 'Session' AND id = $1`, [key]);
        } else if (kind === 'portal' || kind === 'gateway') {
          await pool.query('DELETE FROM idp_web_sessions WHERE kind = $1 AND key = $2', [kind, key]);
        }
      }

      await writeAudit(req, req.adminSession!.email, 'session.kill', email ?? `${kind}:${key.slice(0, 12)}…`, { kind, keyPrefix: key.slice(0, 12), revoked });
      res.redirect('/admin/sessions');
    } catch (err) { next(err); }
  });

  router.post('/sessions/signout-user', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) { res.status(400).render('error', { message: 'Invalid form submission — please retry.' }); return; }
      const email = String(req.body.email ?? '').trim().toLowerCase();
      const { rows } = await pool.query<{ id: string }>('SELECT id FROM idp_users WHERE email = $1', [email]);
      if (!rows[0]) { res.status(404).render('error', { message: 'No IdP user with that email.' }); return; }
      const revoked = await revokeAllSessions(rows[0].id, email);
      await writeAudit(req, req.adminSession!.email, 'user.signout_all', email, { revoked });
      res.redirect('/admin/sessions');
    } catch (err) { next(err); }
  });

  // ── Sign-in events + anomaly alerts ─────────────────────────────────────
  router.get('/logins', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const [{ rows: events }, { rows: alerts }] = await Promise.all([
        pool.query(
          `SELECT email, success, reason, ip, created_at FROM idp_login_events
           ORDER BY id DESC LIMIT 100`,
        ),
        pool.query(
          `SELECT email, COUNT(*) AS failures FROM idp_login_events
           WHERE success = FALSE AND created_at > NOW() - INTERVAL '15 minutes'
           GROUP BY email HAVING COUNT(*) >= 5 ORDER BY failures DESC`,
        ),
      ]);
      res.render('admin/logins', { events, alerts, adminEmail: req.adminSession!.email });
    } catch (err) { next(err); }
  });

  return router;
}
