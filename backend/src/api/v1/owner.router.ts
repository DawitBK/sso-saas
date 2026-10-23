/**
 * Owner verification API (docs/sso/SSO-OPERATIONS.md, "Owner verification"), mounted at /api/v1/owner/verification.
 *
 *   GET  /status                status in plain facts, the owner-only operations with their warnings, and a CSRF token
 *   GET  /csrf                  a CSRF token
 *   POST /start                 { operation, target? }                       -> a challenge for ONE operation
 *   POST /answer-questions      { challengeId, answers: [3 strings] }
 *   POST /send-email-code       { challengeId }
 *   POST /verify-email-code     { challengeId, code }
 *   POST /verify-recovery-code  { challengeId, code }                         only while the emailed code cannot be used
 *   POST /verify-totp           { challengeId, code }                         the authenticator app code (refused when the enrolment was made without one)
 *   POST /finish                { challengeId }                               -> { ticket, expiresAt, operation, audience }
 *
 * The ticket is sent back in the header `X-Owner-Authorisation` on the one request it is for (owner/middleware.ts).
 * The order of the steps and every limit are enforced in owner/challenge.ts. Only the platform administrator's session reaches any of it: everyone else
 * (not signed in as an administrator, or an administrator who is not the platform administrator) is answered as if the endpoint did not exist.
 * Mutations carry a CSRF token (double submit, its own cookie scoped to /api/v1/owner so it reaches these routes).
 */
import crypto from 'node:crypto';
import express, { Router, type NextFunction, type Request, type Response } from 'express';
import { writeAudit } from '../../admin/audit.js';
import { requireAdminJson } from '../../admin/requireAdmin.js';
import { isPlatformAdminSession } from '../../auth/platform-admin.js';
import { IDP_CONFIG } from '../../config.js';
import { reuseOrIssueCsrf } from '../../http/csrf-token.js';
import { createLimiter } from '../../infrastructure/rateLimiter.js';
import { recentOwnerAudit } from '../../owner/audit.js';
import {
  OwnerError,
  answerQuestions,
  finishChallenge,
  ownerStatus,
  sendEmailCode,
  startChallenge,
  verifyEmailCode,
  verifyRecoveryCode,
  verifyTotpStep,
  type OwnerContext,
} from '../../owner/challenge.js';
import { sendOwnerError } from '../../owner/middleware.js';
import { httpOperations } from '../../owner/registry.js';
import { ownerVerificationRequired } from '../../owner/runtime.js';
import { resolveSession } from '../../owner/session.js';
import { sendError, sendOk } from './platform.router.js';

export const OWNER_CSRF_COOKIE = 'idp_owner_csrf';

function issueOwnerCsrf(res: Response): string {
  return reuseOrIssueCsrf(res, OWNER_CSRF_COOKIE, {
    httpOnly: true,
    sameSite: 'lax',
    secure: IDP_CONFIG.isProd,
    path: `${IDP_CONFIG.publicBasePath}/api/v1/owner`,
  });
}

function csrfOk(req: Request): boolean {
  const header = req.headers.cookie ?? '';
  let cookie = '';
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === OWNER_CSRF_COOKIE) cookie = decodeURIComponent(part.slice(i + 1).trim());
  }
  const submitted = typeof req.body?.csrf === 'string' ? (req.body.csrf as string) : '';
  if (!cookie || !submitted || cookie.length !== submitted.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(submitted));
}

type Handler = (ctx: OwnerContext, req: Request, res: Response) => Promise<void>;

export function ownerVerificationRouter(): Router {
  const router = Router();
  router.use(createLimiter('owner-verification', { windowMs: 60_000, limit: 60 }));
  router.use(express.json({ limit: '16kb' }));
  router.use(requireAdminJson(sendError));

  /** The platform administrator only; everyone else is told the endpoint does not exist. Builds the context every step needs. */
  const owner =
    (handler: Handler, opts: { mutating: boolean }) =>
    async (req: Request, res: Response, next: NextFunction): Promise<void> => {
      try {
        const resolved = await resolveSession(req);
        if (!resolved || !(await isPlatformAdminSession(resolved.session))) {
          sendError(res, 404, 'ERR-NOT-FOUND', 'Not found.');
          return;
        }
        if (opts.mutating && !csrfOk(req)) {
          sendError(res, 403, 'ERR-INVALID-CSRF', 'Invalid CSRF token');
          return;
        }
        const ctx: OwnerContext = {
          accountId: resolved.session.accountId,
          sessionHash: resolved.sessionHash,
          chainAudit: (action, detail) => writeAudit(req, resolved.session.email, action, 'platform', detail),
        };
        res.set('cache-control', 'no-store');
        await handler(ctx, req, res);
      } catch (err) {
        if (err instanceof OwnerError) {
          sendOwnerError(res, err.status, err.code, err.message, err.extra);
          return;
        }
        next(err);
      }
    };

  router.get(
    '/status',
    owner(async (ctx, _req, res) => {
      const status = await ownerStatus(ctx.accountId);
      sendOk(res, {
        required: ownerVerificationRequired(),
        ...status,
        operations: httpOperations().map((o) => ({ key: o.key, label: o.label, warning: o.warning, audience: o.audience, needsTarget: o.needsTarget })),
        recent: await recentOwnerAudit(15),
        csrf: issueOwnerCsrf(res),
      });
    }, { mutating: false }),
  );

  router.get(
    '/csrf',
    owner(async (_ctx, _req, res) => {
      sendOk(res, { csrf: issueOwnerCsrf(res) });
    }, { mutating: false }),
  );

  router.post('/start', owner(async (ctx, req, res) => {
    sendOk(res, await startChallenge(ctx, { operation: String(req.body?.operation ?? ''), target: typeof req.body?.target === 'string' ? req.body.target : undefined }));
  }, { mutating: true }));

  router.post('/answer-questions', owner(async (ctx, req, res) => {
    sendOk(res, await answerQuestions(ctx, String(req.body?.challengeId ?? ''), req.body?.answers));
  }, { mutating: true }));

  router.post('/send-email-code', owner(async (ctx, req, res) => {
    sendOk(res, await sendEmailCode(ctx, String(req.body?.challengeId ?? '')));
  }, { mutating: true }));

  router.post('/verify-email-code', owner(async (ctx, req, res) => {
    sendOk(res, await verifyEmailCode(ctx, String(req.body?.challengeId ?? ''), req.body?.code));
  }, { mutating: true }));

  router.post('/verify-recovery-code', owner(async (ctx, req, res) => {
    sendOk(res, await verifyRecoveryCode(ctx, String(req.body?.challengeId ?? ''), req.body?.code));
  }, { mutating: true }));

  router.post('/verify-totp', owner(async (ctx, req, res) => {
    sendOk(res, await verifyTotpStep(ctx, String(req.body?.challengeId ?? ''), req.body?.code));
  }, { mutating: true }));

  router.post('/finish', owner(async (ctx, req, res) => {
    const t = await finishChallenge(ctx, String(req.body?.challengeId ?? ''));
    sendOk(res, { ticket: t.ticket, expiresAt: t.expiresAt.toISOString(), operation: t.operation, audience: t.audience });
  }, { mutating: true }));

  return router;
}
