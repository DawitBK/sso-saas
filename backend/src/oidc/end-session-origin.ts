/**
 * The sign-out pages are built for the issuer's own address, never for whatever Host the last proxy happened to send.
 *
 * oidc-provider renders the auto-submitted sign-out form (and the redirect after it) with absolute URLs taken from the request's Host. Behind a chain of
 * proxies that is not always the address the browser used: on the mirror, Apache does not preserve the Host, the Next.js frontend in between then
 * reports its own `127.0.0.1:9301`, and the page posted its form there. The browser (and the page's `form-action 'self'` policy) refuses a form that
 * leaves the origin, so sign-out ended on a page that never finished. Pinning the host and scheme of the issuer for these routes makes the result the
 * same on every route to the SSO (direct, behind Apache with or without ProxyPreserveHost, behind the hosted edition's frontend and tunnel).
 *
 * Only the end-session routes are pinned. The rest of the provider keeps trusting the proxy headers exactly as before (provider.proxy, TRUST_PROXY_HOPS),
 * so no sign-in, token or discovery URL changes.
 */
export const END_SESSION_PATH = /\/session\/end(\/|$)/;

interface KoaLikeContext {
  path: string;
  request: object;
}

export function pinEndSessionOrigin(issuer: string): (ctx: KoaLikeContext, next: () => Promise<unknown>) => Promise<void> {
  const { host, protocol } = new URL(issuer);
  const scheme = protocol.replace(/:$/, '');
  return async (ctx, next) => {
    if (END_SESSION_PATH.test(ctx.path)) {
      Object.defineProperty(ctx.request, 'host', { configurable: true, get: () => host });
      Object.defineProperty(ctx.request, 'protocol', { configurable: true, get: () => scheme });
    }
    await next();
  };
}
