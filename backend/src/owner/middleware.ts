/**
 * `requireOwnerAuthorisation(operationKey)`: the one gate every owner-only operation passes through (registry.ts lists them).
 *
 * What it enforces, on the server, per request:
 *   1. when OWNER_VERIFICATION_REQUIRED is false (development, tests) it does nothing, so development stays unrestricted;
 *   2. the session must be the platform administrator's (isPlatformAdminSession). As middleware it LEAVES a non-owner to the route's own check, which
 *      answers exactly what it always did (403 ERR-PLATFORM-ADMIN-ONLY, with that route's own words); the inline form answers that 403 itself;
 *   3. the owner must be enrolled and the store readable, else OWNER_NOT_ENROLLED / OWNER_STORE_UNREADABLE: REFUSED, never allowed;
 *   4. the header `X-Owner-Authorisation` must carry a ticket issued by the sequence for THIS operation (and this target), to THIS session, for this
 *      account, not expired, not used (verifyAndReserveTicket). It is reserved atomically; when the request ends it is spent, or released if the request
 *      was refused with a 4xx (so a typo in a form does not cost a whole new sequence);
 *   5. the outcome is audited without secrets and raised as a security event (Phase 5 subscribes; nothing here contains containment logic).
 *
 * A missing ticket is the normal first step of the console (the dialog opens on the 403), so it is raised at `info`; a presented but rejected ticket,
 * a non-owner reaching an owner-only operation, and an unenrolled/unreadable store are raised at `warning`.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { writeAudit } from '../admin/audit.js';
import { isPlatformAdminSession } from '../auth/platform-admin.js';
import { logger } from '../logging/logger.js';
import { emitSecurityEvent } from '../ops/securityEvents.js';
import { ownerAudit } from './audit.js';
import { findOperation, targetHash } from './registry.js';
import { ownerVerificationRequired } from './runtime.js';
import { resolveSession } from './session.js';
import { readStore } from './store.js';
import { finishTicket, verifyAndReserveTicket, type TicketProblem } from './ticket.js';

export const OWNER_HEADER = 'x-owner-authorisation';

/** Error envelope with extra fields inside `error` (the shared sendError carries only code, message and field details). */
export function sendOwnerError(res: Response, status: number, code: string, message: string, extra: Record<string, unknown> = {}): void {
  res.status(status).json({ error: { code, message, ...extra }, meta: { requestId: String(res.locals.requestId ?? '') } });
}

const PROBLEM_MESSAGE: Record<TicketProblem, string> = {
  malformed: 'The owner authorisation was not understood. Verify again.',
  signature: 'The owner authorisation could not be verified. Verify again.',
  expired: 'The owner authorisation has expired. Verify again.',
  wrong_operation: 'That owner authorisation is for a different action. Verify again for this one.',
  wrong_target: 'That owner authorisation is for something else. Verify again for this one.',
  wrong_session: 'That owner authorisation belongs to a different sign-in. Verify again.',
  wrong_account: 'That owner authorisation belongs to a different account. Verify again.',
  wrong_audience: 'That owner authorisation is for a different system. Verify again.',
  unknown: 'The owner authorisation is not known. Verify again.',
  used: 'That owner authorisation was already used. Verify again.',
};

/**
 * Decide whether the request may proceed. Returns true to continue; false means a response has been sent.
 * `leaveNonOwner`: as middleware, a session that is not the platform administrator's is not decided here (the route refuses it itself).
 */
export async function authoriseOwnerOperation(
  req: Request,
  res: Response,
  operationKey: string,
  target?: string,
  opts: { leaveNonOwner?: boolean } = {},
): Promise<boolean> {
  if (!ownerVerificationRequired()) return true;
  const op = findOperation(operationKey);
  if (!op) {
    // A route naming an operation that is not in the registry is a programming error: refuse rather than guess.
    logger.error({ operationKey }, '[idp:owner:ALERT] a route named an unknown owner operation; refusing');
    sendOwnerError(res, 500, 'ERR-INTERNAL', 'Internal error');
    return false;
  }
  const resolved = await resolveSession(req);
  const session = resolved?.session ?? (req as Request & { adminSession?: { accountId?: string } }).adminSession;
  if (!session || !resolved) {
    sendOwnerError(res, 401, 'ERR-NOT-AUTHENTICATED', 'Authentication required');
    return false;
  }
  const actor = { userId: (session as { accountId: string }).accountId, sessionId: resolved.sessionHash.slice(0, 8), ip: req.ip };
  const hint = { operation: op.key, target: op.needsTarget ? (target ?? '') : null, label: op.label, warning: op.warning };

  if (!(await isPlatformAdminSession(session as { accountId?: string }))) {
    emitSecurityEvent({ kind: 'owner_op_denied', severity: 'warning', actor, operation: op.key, detail: { reason: 'not_platform_admin' } });
    await ownerAudit('operation_denied', 'denied', { operation: op.key, sessionHash: resolved.sessionHash, detail: { reason: 'not_platform_admin' } });
    if (opts.leaveNonOwner) return true;
    sendOwnerError(res, 403, 'ERR-PLATFORM-ADMIN-ONLY', 'Only the platform administrator can do this.');
    return false;
  }

  const accountId = (session as { accountId: string }).accountId;
  const store = await readStore();
  if (store.state !== 'ok' || store.doc.accountId !== accountId) {
    const unreadable = store.state === 'unreadable';
    const code = unreadable ? 'OWNER_STORE_UNREADABLE' : 'OWNER_NOT_ENROLLED';
    emitSecurityEvent({ kind: 'owner_op_denied', severity: 'warning', actor, operation: op.key, detail: { reason: unreadable ? 'store_unreadable' : 'not_enrolled' } });
    await ownerAudit('operation_denied', 'denied', { operation: op.key, sessionHash: resolved.sessionHash, detail: { reason: unreadable ? 'store_unreadable' : 'not_enrolled' } });
    sendOwnerError(
      res,
      403,
      code,
      unreadable
        ? 'Owner verification cannot be read on this server, so this action is refused until it is repaired.'
        : 'Owner verification has not been set up yet, so this action is refused. The owner must enrol at a terminal on the server first.',
      hint,
    );
    return false;
  }

  const token = String(req.get(OWNER_HEADER) ?? '').trim();
  if (!token) {
    emitSecurityEvent({ kind: 'owner_op_without_sequence', severity: 'info', actor, operation: op.key, detail: {} });
    await ownerAudit('operation_without_ticket', 'denied', { operation: op.key, sessionHash: resolved.sessionHash });
    sendOwnerError(res, 403, 'OWNER_AUTHORISATION_REQUIRED', 'This action needs your owner authorisation.', hint);
    return false;
  }

  const outcome = await verifyAndReserveTicket(token, {
    operation: op.key,
    targetHash: targetHash(op.key, target),
    sessionHash: resolved.sessionHash,
    accountId,
  });
  if ('problem' in outcome) {
    emitSecurityEvent({ kind: 'owner_op_denied', severity: 'warning', actor, operation: op.key, detail: { reason: outcome.problem } });
    await ownerAudit('operation_denied', 'denied', { operation: op.key, sessionHash: resolved.sessionHash, detail: { reason: outcome.problem } });
    sendOwnerError(res, 403, 'OWNER_AUTHORISATION_INVALID', PROBLEM_MESSAGE[outcome.problem], hint);
    return false;
  }

  // The ticket is reserved: spend it when the request ends (or release it after a 4xx).
  const { jti } = outcome;
  res.once('finish', () => {
    finishTicket(jti, res.statusCode)
      .then(async (state) => {
        if (state === 'consumed' && res.statusCode < 400) {
          await ownerAudit('operation_authorised', 'ok', { operation: op.key, sessionHash: resolved.sessionHash });
          await writeAudit(req, (session as { email?: string }).email ?? 'platform', 'owner.operation.authorised', 'platform', { operation: op.key });
        }
      })
      .catch((err) => logger.error({ err, operation: op.key }, '[idp:owner] could not finish an owner ticket'));
  });
  return true;
}

/** The route-level form. `targetFrom` names what the operation acts on (a key id, a system, a client id...). */
export function requireOwnerAuthorisation(operationKey: string, targetFrom?: (req: Request) => string | undefined): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (await authoriseOwnerOperation(req, res, operationKey, targetFrom?.(req), { leaveNonOwner: true })) next();
    } catch (err) {
      next(err);
    }
  };
}
