/**
 * CSV exports of the two logs an auditor asks for: the admin audit trail and the sign-in log.
 *
 *   GET /api/v1/admin/audit/export    the filtered audit trail (same filters as the Audit page)
 *   GET /api/v1/admin/logins/export   the filtered sign-in log (same filters as the Sign-ins page)
 *
 * Both are mounted ahead of admin.router.ts. They apply the same platform-administrator exclusions as the pages, cap at
 * MAX_EXPORT_ROWS (and say so in `x-export-truncated`), neutralise spreadsheet formulas (http/csv.ts), and are themselves written to
 * the audit trail: who took a copy of the trail, and when, is part of the trail.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { listAudit, writeAudit } from '../../admin/audit.js';
import { buildLoginFilter } from '../../admin/services/login-filters.js';
import { csvRow, sendCsv } from '../../http/csv.js';
import { pool } from '../../db/pool.js';
import type { PortalSession } from '../../portal/session.js';
import { parseIsoDate } from './admin.router.js';
import { sendError } from './platform.router.js';

export const MAX_EXPORT_ROWS = 10_000;

export function activityRouter(): Router {
  const router = Router();
  router.use(requireAdminJson(sendError));

  router.get('/audit/export', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      const filter = {
        q: String(req.query.q ?? '').trim().slice(0, 200),
        action: String(req.query.action ?? '').trim().slice(0, 80),
        actor: String(req.query.actor ?? '').trim().slice(0, 200),
        from: parseIsoDate(req.query.from),
        to: parseIsoDate(req.query.to),
      };
      const rows = await listAudit(filter, MAX_EXPORT_ROWS + 1, 0);
      const truncated = rows.length > MAX_EXPORT_ROWS;
      const out = rows.slice(0, MAX_EXPORT_ROWS);
      const lines = [
        csvRow(['sequence', 'when', 'actor', 'action', 'target', 'detail', 'address']),
        ...out.map((r) => csvRow([r.sequence_number, new Date(r.created_at).toISOString(), r.actor_email, r.action, r.target, JSON.stringify(r.detail ?? {}), r.ip])),
      ];
      await writeAudit(req, session.email, 'audit.export', 'audit', { rows: out.length, truncated, filters: { ...filter, q: filter.q ? '(set)' : '', actor: filter.actor ? '(set)' : '' } });
      sendCsv(res, `audit-${new Date().toISOString().slice(0, 10)}.csv`, lines, { 'x-export-rows': String(out.length), 'x-export-truncated': String(truncated) });
    } catch (err) {
      next(err);
    }
  });

  router.get('/logins/export', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = (req as Request & { adminSession?: PortalSession }).adminSession as PortalSession;
      const filter = String(req.query.filter ?? '');
      const f = buildLoginFilter({
        success: filter === 'success' ? true : filter === 'failed' ? false : null,
        q: String(req.query.q ?? '').trim().slice(0, 200),
        reason: String(req.query.reason ?? '').trim().slice(0, 40),
        from: parseIsoDate(req.query.from),
        to: parseIsoDate(req.query.to),
      });
      const { rows } = await pool.query(
        `SELECT e.created_at, e.email, e.success, e.reason, e.ip, e.user_agent
           FROM idp_login_events e LEFT JOIN idp_users u ON lower(u.email) = e.email
           ${f.where}
          ORDER BY e.id DESC LIMIT $${f.params.length + 1}`,
        [...f.params, MAX_EXPORT_ROWS + 1],
      );
      const truncated = rows.length > MAX_EXPORT_ROWS;
      const out = rows.slice(0, MAX_EXPORT_ROWS);
      const lines = [
        csvRow(['when', 'email', 'result', 'reason', 'address', 'browser']),
        ...out.map((r) => csvRow([new Date(r.created_at).toISOString(), r.email, r.success ? 'success' : 'failed', r.reason, r.ip, r.user_agent])),
      ];
      await writeAudit(req, session.email, 'logins.export', 'logins', { rows: out.length, truncated });
      sendCsv(res, `sign-ins-${new Date().toISOString().slice(0, 10)}.csv`, lines, { 'x-export-rows': String(out.length), 'x-export-truncated': String(truncated) });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
