/**
 * Users list: CSV export and bulk actions.
 *
 *   GET  /api/v1/admin/users/export   the current filtered list as CSV (same query string as the list; at most MAX_EXPORT_ROWS)
 *   POST /api/v1/admin/users/bulk     { ids, action: 'disable' | 'enable' | 'sign-out', csrf } for up to MAX_BULK people
 *
 * Both are mounted ahead of admin.router.ts so "export" and "bulk" are never read as a user id. The platform administrator is outside
 * every list and every action: an id naming it answers exactly like an id that does not exist.
 *
 * A bulk action is not a shortcut around the single-user rules: it runs the same refusals (an administrator cannot disable their own
 * account), the same session revocation, and writes the same audit row per person as the one-at-a-time buttons, plus nothing else.
 */
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { writeAudit } from '../../admin/audit.js';
import { csvCell, csvRow, sendCsv } from '../../http/csv.js';
import { resolveUserListQuery } from '../../admin/services/user-query.js';
import { selfDisableRefusal } from '../../admin/user-guards.js';
import { isPlatformAdminId } from '../../auth/platform-admin.js';
import { disableWarning, revokeAllSessions } from '../../auth/revoke.js';
import { pool } from '../../db/pool.js';
import type { PortalSession } from '../../portal/session.js';
import { validateAdminApiCsrf } from './admin.router.js';
import { sendError, sendOk } from './platform.router.js';

export const MAX_EXPORT_ROWS = 10_000;
export const MAX_BULK = 200;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ACTIONS = ['disable', 'enable', 'sign-out'] as const;
type BulkAction = (typeof ACTIONS)[number];

export { csvCell, csvRow };

export function usersBulkRouter(): Router {
  const router = Router();
  router.use(express.json({ limit: '256kb' }));
  router.use(requireAdminJson(sendError));

  router.get('/export', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      const resolved = await resolveUserListQuery(req.query as Record<string, unknown>, String(res.locals.requestId ?? ''));
      if (!resolved.ok) {
        sendError(res, resolved.status, resolved.code, resolved.message);
        return;
      }
      const { filter, orderBy, view } = resolved;
      const { rows } = await pool.query(
        `SELECT u.email, u.given_name, u.family_name, u.source, u.is_active, u.totp_enabled, u.must_change_password,
                u.last_login_at, u.created_at,
                (SELECT COUNT(*) FROM idp_user_groups g WHERE g.user_id = u.id) AS group_count
           FROM idp_users u ${filter.where}
          ORDER BY ${orderBy}
          LIMIT $${filter.params.length + 1}`,
        [...filter.params, MAX_EXPORT_ROWS + 1],
      );
      const truncated = rows.length > MAX_EXPORT_ROWS;
      const out = rows.slice(0, MAX_EXPORT_ROWS);
      const lines = [
        csvRow(['email', 'first_name', 'last_name', 'account_type', 'status', 'two_factor', 'must_change_password', 'groups', 'last_sign_in', 'created']),
        ...out.map((r) =>
          csvRow([
            r.email, r.given_name, r.family_name, r.source === 'ad' ? 'Active Directory' : 'Local', r.is_active ? 'active' : 'disabled',
            r.totp_enabled ? 'enrolled' : 'not enrolled', r.must_change_password ? 'yes' : 'no', r.group_count,
            r.last_login_at ? new Date(r.last_login_at).toISOString() : '', new Date(r.created_at).toISOString(),
          ]),
        ),
      ];
      await writeAudit(req, session.email, 'users.export', 'users', { rows: out.length, truncated, filters: { ...view, q: view.q ? '(set)' : '' } });
      sendCsv(res, `users-${new Date().toISOString().slice(0, 10)}.csv`, lines, { 'x-export-rows': String(out.length), 'x-export-truncated': String(truncated) });
    } catch (err) {
      next(err);
    }
  });

  router.post('/bulk', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateAdminApiCsrf(req)) {
        sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
        return;
      }
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      const body = req.body as { ids?: unknown; action?: unknown };
      const action = String(body.action) as BulkAction;
      if (!(ACTIONS as readonly string[]).includes(action)) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', `action must be one of: ${ACTIONS.join(', ')}.`);
        return;
      }
      if (!Array.isArray(body.ids) || body.ids.some((id) => typeof id !== 'string' || !UUID.test(id))) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', 'ids must be a list of user ids.');
        return;
      }
      const ids = [...new Set(body.ids as string[])];
      if (ids.length === 0 || ids.length > MAX_BULK) {
        sendError(res, 400, 'ERR-VALIDATION-FAILED', `Choose between 1 and ${MAX_BULK} people.`);
        return;
      }

      const results: Array<{ id: string; email: string | null; outcome: 'changed' | 'skipped' | 'refused'; message?: string }> = [];
      let warnings = 0;
      for (const id of ids) {
        // The platform administrator does not exist for this console: the same answer as an id that was never there.
        const { rows } = (await isPlatformAdminId(id))
          ? { rows: [] as Array<{ email: string; is_active: boolean }> }
          : await pool.query<{ email: string; is_active: boolean }>('SELECT email, is_active FROM idp_users WHERE id = $1', [id]);
        const user = rows[0];
        if (!user) {
          results.push({ id, email: null, outcome: 'refused', message: 'User not found.' });
          continue;
        }
        if (action === 'disable') {
          const self = selfDisableRefusal(session.accountId, id);
          if (self) { results.push({ id, email: user.email, outcome: 'refused', message: self }); continue; }
          if (!user.is_active) { results.push({ id, email: user.email, outcome: 'skipped', message: 'Already disabled.' }); continue; }
          await pool.query('UPDATE idp_users SET is_active = FALSE, updated_at = NOW() WHERE id = $1', [id]);
          const revoked = await revokeAllSessions(id, user.email);
          if (disableWarning(revoked)) warnings += 1;
          await writeAudit(req, session.email, 'user.disable', user.email, { userId: id, revoked, bulk: true });
        } else if (action === 'enable') {
          if (user.is_active) { results.push({ id, email: user.email, outcome: 'skipped', message: 'Already active.' }); continue; }
          await pool.query('UPDATE idp_users SET is_active = TRUE, updated_at = NOW() WHERE id = $1', [id]);
          await writeAudit(req, session.email, 'user.enable', user.email, { userId: id, bulk: true });
        } else {
          const revoked = await revokeAllSessions(id, user.email);
          if (disableWarning(revoked)) warnings += 1;
          await writeAudit(req, session.email, 'user.signout_all', user.email, { userId: id, revoked, bulk: true });
        }
        results.push({ id, email: user.email, outcome: 'changed' });
      }
      const count = (o: string) => results.filter((r) => r.outcome === o).length;
      sendOk(res, { action, results, summary: { changed: count('changed'), skipped: count('skipped'), refused: count('refused'), notFullyDark: warnings } });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
