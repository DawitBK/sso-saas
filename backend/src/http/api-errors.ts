/**
 * What the last-stop error handler says when a route throws instead of answering.
 *
 * Routes answer the failures they expect themselves (`sendError` with a specific code and sentence). This module is the safety net for
 * everything else, so that the caller still gets a professional, typed answer and never a bare 500 for a mistake that was theirs:
 *
 *   - a database constraint reached because a validator and the schema disagree (value too long, NOT NULL, CHECK, foreign key,
 *     duplicate): 4xx, naming the field in words a person recognises;
 *   - a request body that is not JSON, or is too large, or an encoding the server does not read: 400, 413 or 415;
 *   - a malformed identifier in a URL or body (Postgres 22P02): 400;
 *   - anything else that carries a 4xx `status`: that status with its standard code;
 *   - the rest: 500 `ERR-INTERNAL`, and the message never carries the cause (it goes to the log).
 *
 * The text is fixed here, never copied from the error, so a driver message cannot leak a table name, a query or a value.
 */

import type { ErrorRequestHandler } from 'express';
import { logger } from '../logging/logger.js';
import { GateBusyError } from '../infrastructure/workGate.js';

export interface DescribedError {
  status: number;
  code: string;
  message: string;
  /** Set when the answer came from a database constraint: the caller's validator should have caught it, so the log records it. */
  constraint?: string;
}

interface PgFields {
  code?: string;
  table?: string;
  column?: string;
  constraint?: string;
}

function pgFields(err: unknown): PgFields {
  if (!err || typeof err !== 'object') return {};
  const e = err as Record<string, unknown>;
  const str = (key: string): string | undefined => (typeof e[key] === 'string' ? (e[key] as string) : undefined);
  return { code: str('code'), table: str('table'), column: str('column'), constraint: str('constraint') };
}

const COLUMN_LABELS: Record<string, string> = {
  email: 'email address',
  given_name: 'first name',
  family_name: 'last name',
  name: 'name',
  client_id: 'application id',
  redirect_uris: 'redirect addresses',
  post_logout_redirect_uris: 'sign-out addresses',
  note: 'note',
  reason: 'reason',
  source: 'account source',
  status: 'status',
  kind: 'kind',
  value: 'value',
};

const TABLE_LABELS: Record<string, string> = {
  idp_users: 'user',
  idp_clients: 'application',
  idp_settings: 'setting',
  idp_password_reset_requests: 'password reset request',
  idp_audit_chain_acknowledgements: 'audit-chain acknowledgement',
  idp_recovery_codes: 'recovery code',
  idp_user_groups: 'group membership',
  idp_app_entitlements: 'application access',
  idp_client_roles: 'application role',
  idp_client_user_roles: 'application role assignment',
};

/** Constraints a person can plausibly hit, with a sentence of their own (the generic text is the fallback). */
const CONSTRAINT_MESSAGES: Record<string, { status: number; code: string; message: string }> = {
  idp_users_email_key: { status: 409, code: 'ERR-EMAIL-EXISTS', message: 'A user with that email already exists.' },
};

function label(map: Record<string, string>, key: string | undefined, fallback: string): string {
  if (!key) return fallback;
  return map[key] ?? key.replace(/^idp_/, '').replace(/_/g, ' ');
}

function capitalise(text: string): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text;
}

/** A Postgres error as a typed answer, or null when the error is not one of the constraint families. */
export function describeDatabaseError(err: unknown): DescribedError | null {
  const f = pgFields(err);
  if (!f.code) return null;
  const entity = label(TABLE_LABELS, f.table, 'record');
  const field = label(COLUMN_LABELS, f.column, 'a required field');

  switch (f.code) {
    case '23505': {
      const known = f.constraint ? CONSTRAINT_MESSAGES[f.constraint] : undefined;
      if (known) return { ...known, constraint: f.constraint };
      return { status: 409, code: 'ERR-DUPLICATE', message: `A ${entity} with these details already exists.`, constraint: f.constraint };
    }
    case '23502':
      return { status: 400, code: 'ERR-REQUIRED-FIELD', message: `${capitalise(field)} is required.`, constraint: f.column };
    case '23503':
      return { status: 409, code: 'ERR-REFERENCE', message: `This change refers to, or is still used by, another record. Refresh and try again.`, constraint: f.constraint };
    case '23514':
      return { status: 422, code: 'ERR-CONSTRAINT-VIOLATION', message: `That value is not allowed for a ${entity}.`, constraint: f.constraint };
    case '22001':
      return { status: 400, code: 'ERR-VALUE-TOO-LONG', message: 'One of the values provided is longer than allowed.' };
    case '22003':
      return { status: 400, code: 'ERR-VALUE-OUT-OF-RANGE', message: 'One of the numbers provided is out of the allowed range.' };
    case '22021':
    case '22P02':
      return { status: 400, code: 'ERR-VALIDATION-FAILED', message: 'One of the values provided is not in a valid format.' };
    default:
      return null;
  }
}

const REQUEST_ERROR_TYPES: Record<string, { status: number; code: string; message: string }> = {
  'entity.parse.failed': { status: 400, code: 'ERR-INVALID-JSON', message: 'The request body is not valid JSON.' },
  'request.aborted': { status: 400, code: 'ERR-REQUEST-ABORTED', message: 'The request was interrupted before it finished.' },
  'request.size.invalid': { status: 400, code: 'ERR-VALIDATION-FAILED', message: 'The request size did not match what was sent.' },
  'entity.too.large': { status: 413, code: 'ERR-PAYLOAD-TOO-LARGE', message: 'The request is larger than the server accepts.' },
  'encoding.unsupported': { status: 415, code: 'ERR-UNSUPPORTED-MEDIA-TYPE', message: 'The content encoding of the request is not supported.' },
  'charset.unsupported': { status: 415, code: 'ERR-UNSUPPORTED-MEDIA-TYPE', message: 'The character set of the request is not supported.' },
};

/** One standard code and sentence per client-error status, so no 4xx leaves the server as an anonymous "could not be processed". */
const STATUS_ANSWERS: Record<number, { code: string; message: string }> = {
  400: { code: 'ERR-VALIDATION-FAILED', message: 'The request could not be understood.' },
  401: { code: 'ERR-NOT-AUTHENTICATED', message: 'Sign in to continue.' },
  403: { code: 'ERR-FORBIDDEN', message: 'You do not have permission to do that.' },
  404: { code: 'ERR-NOT-FOUND', message: 'That does not exist.' },
  405: { code: 'ERR-METHOD-NOT-ALLOWED', message: 'That method is not allowed here.' },
  409: { code: 'ERR-CONFLICT', message: 'That conflicts with the current state. Refresh and try again.' },
  413: { code: 'ERR-PAYLOAD-TOO-LARGE', message: 'The request is larger than the server accepts.' },
  415: { code: 'ERR-UNSUPPORTED-MEDIA-TYPE', message: 'That content type is not supported.' },
  422: { code: 'ERR-UNPROCESSABLE', message: 'The request was understood but cannot be applied.' },
  429: { code: 'ERR-RATE-LIMITED', message: 'Too many requests. Wait a moment and try again.' },
};

/** A malformed or oversized request, or an error that declared its own 4xx status; null for anything else. */
export function describeRequestError(err: unknown): DescribedError | null {
  if (!err || typeof err !== 'object') return null;
  const e = err as { type?: unknown; status?: unknown; statusCode?: unknown };
  if (typeof e.type === 'string' && REQUEST_ERROR_TYPES[e.type]) return { ...REQUEST_ERROR_TYPES[e.type] };
  const status = typeof e.status === 'number' ? e.status : typeof e.statusCode === 'number' ? e.statusCode : undefined;
  if (status && status >= 400 && status < 500) {
    const known = STATUS_ANSWERS[status];
    return { status, code: known?.code ?? 'ERR-REQUEST', message: known?.message ?? 'The request could not be processed.' };
  }
  return null;
}

export const INTERNAL_ANSWER: DescribedError = { status: 500, code: 'ERR-INTERNAL', message: 'Something went wrong.' };

/** The answer for any error that reaches the last-stop handler. */
export function describeError(err: unknown): DescribedError {
  return describeDatabaseError(err) ?? describeRequestError(err) ?? INTERNAL_ANSWER;
}

/**
 * Last stop for an error thrown by any route: log it, answer with the typed result above. Without it Express's default handler prints the
 * stack trace in every environment but production and a malformed id in a URL surfaced as a bare 500 page.
 */
export function lastStopErrorHandler(): ErrorRequestHandler {
  return (err, req, res, next) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    const wantsJson = req.path.startsWith('/api/') || req.accepts(['json', 'html']) === 'json';
    // The password-check gate is full: a 503 with Retry-After, not a 500 (and not logged as a fault: it is load, and the gate counts it).
    if (err instanceof GateBusyError) {
      res.set('retry-after', '5');
      if (wantsJson) res.status(503).json({ error: { code: 'ERR-BUSY', message: 'The service is busy. Please try again in a few seconds.' } });
      else res.status(503).type('text/plain').send('The service is busy. Please try again in a few seconds.');
      return;
    }
    const answer = describeError(err);
    if (answer.status >= 500) {
      logger.error({ err, method: req.method, path: req.path }, '[idp] unhandled route error');
    } else if (answer.constraint !== undefined) {
      // A caller reached the database with a value the route's own validation should have refused: the validator and the schema disagree.
      logger.warn({ code: answer.code, constraint: answer.constraint, method: req.method, path: req.path }, '[idp] a database constraint answered the request');
    }
    if (wantsJson) {
      res.status(answer.status).json({ error: { code: answer.code, message: answer.message }, meta: { requestId: String(res.locals.requestId ?? '') } });
    } else {
      res.status(answer.status).type('text/plain').send(answer.status >= 500 ? 'Something went wrong. Please try again, and tell an administrator if it keeps happening.' : answer.message);
    }
  };
}
