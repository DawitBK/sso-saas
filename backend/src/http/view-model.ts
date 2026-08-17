/**
 * View-model contract for SSO UI decoupling.
 *
 * The backend (7300) never renders HTML. Every `res.render(view, locals)`
 * call site (unchanged, still written as if it were rendering EJS) instead
 * produces a JSON `{ view, locals }` payload; the independently deployable
 * frontend (7301) is the only process that turns that into a page.
 */

import type { NextFunction, Request, Response } from 'express';

export const SSO_VIEW_CONTENT_TYPE = 'application/vnd.sso.view+json';

export type SsoViewModel = {
  view: string;
  locals: Record<string, unknown>;
};

/** JSON-safe copy of template locals (Dates → ISO strings; BigInt → string). */
export function serializeLocals(locals: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(
    JSON.stringify(locals, (_key, value: unknown) => {
      if (typeof value === 'bigint') return value.toString();
      return value;
    }),
  ) as Record<string, unknown>;
}

/**
 * Wrap `res.render` so every call site returns `{ view, locals }` JSON
 * instead of rendering HTML, with no other code changes required at the
 * call sites themselves.
 */
export function viewModelMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.render = ((view: string, options?: object, callback?: (err: Error, html: string) => void) => {
    if (typeof options === 'function') {
      callback = options as (err: Error, html: string) => void;
      options = undefined;
    }

    const merged: Record<string, unknown> = {
      ...(res.locals as Record<string, unknown>),
      ...(typeof options === 'object' && options !== null ? (options as Record<string, unknown>) : {}),
    };

    try {
      const payload: SsoViewModel = {
        view,
        locals: serializeLocals(merged),
      };
      res.status(res.statusCode || 200);
      res.set('cache-control', res.get('cache-control') ?? 'no-store');
      res.type(SSO_VIEW_CONTENT_TYPE);
      res.json(payload);
      if (callback) callback(null as unknown as Error, '');
    } catch (err) {
      if (callback) callback(err as Error, '');
      else next(err);
    }
  }) as typeof res.render;

  next();
}
