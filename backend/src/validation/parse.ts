/**
 * SSO request validation (Directive §6.8). SSO's hand-rolled routes split
 * into two established response families that must each keep their own
 * existing shape:
 *
 *  - View-model routes (admin/portal/interactions/bridge): errors already go
 *    through `res.render(view, locals)` (monkey-patched to JSON by
 *    http/view-model.ts). `parseOrRenderView` re-renders the SAME view with
 *    the caller-supplied locals plus a validation-message field, matching
 *    exactly how these routes already report every other kind of error
 *    (bad credentials, expired session, etc.) — it does not introduce a new
 *    generic envelope.
 *  - JSON-API routes (api/v1/platform.router.ts's sendOk/sendError, and
 *    admin/gms-role-grants.routes.ts's `{success,error}` shape):
 *    `parseOrSendError` takes a caller-supplied responder so each keeps its
 *    own existing envelope rather than being forced into one.
 *
 * Both return `null` on failure (after already writing the response) so call
 * sites read as `const parsed = parseOrX(...); if (!parsed) return;`.
 */
import type { Response } from 'express';
import type { z, ZodTypeAny } from 'zod';
import { formatZodIssues, zodIssuesAsDetails } from './format.js';

export function parseOrRenderView<T extends ZodTypeAny>(
  schema: T,
  input: unknown,
  res: Response,
  view: string,
  locals: Record<string, unknown>,
  status = 400,
): { data: z.infer<T> } | null {
  const result = schema.safeParse(input);
  if (!result.success) {
    res.status(status).render(view, { ...locals, error: formatZodIssues(result.error) });
    return null;
  }
  return { data: result.data };
}

export function parseOrSendError<T extends ZodTypeAny>(
  schema: T,
  input: unknown,
  respond: (details: Array<{ field?: string; message: string }>) => void,
): { data: z.infer<T> } | null {
  const result = schema.safeParse(input);
  if (!result.success) {
    respond(zodIssuesAsDetails(result.error));
    return null;
  }
  return { data: result.data };
}
