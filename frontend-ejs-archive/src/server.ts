/**
 * SSO browser entry point on port 7301.
 *
 * Browser UI routes (/portal, /admin, /interaction, /bridge) are fetched from
 * the backend as JSON view models and rendered here with EJS. Everything else
 * (OIDC protocol, /api/v1, health, JWKS) is reverse-proxied over HTTP to 7300.
 */

import dotenv from 'dotenv';
import ejs from 'ejs';
import express from 'express';
import { createProxyMiddleware } from 'http-proxy-middleware';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config({ override: true });

const PORT = Number(process.env.PORT ?? 7301);
const BACKEND = (process.env.SSO_BACKEND_URL ?? 'http://localhost:7300').replace(/\/$/, '');
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VIEWS_DIR = process.env.VIEWS_DIR ?? path.resolve(__dirname, 'views');

const SSO_VIEW_CONTENT_TYPE = 'application/vnd.sso.view+json';

function isUiPath(pathname: string): boolean {
  return (
    pathname === '/' ||
    pathname.startsWith('/portal') ||
    pathname.startsWith('/admin') ||
    pathname.startsWith('/interaction') ||
    pathname.startsWith('/bridge')
  );
}

function hopByHopHeaders(): Set<string> {
  return new Set([
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailers',
    'transfer-encoding',
    'upgrade',
    'host',
    'content-length',
  ]);
}

async function readRequestBody(req: express.Request): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function forwardSetCookies(upstream: Response, res: express.Response): void {
  const getSetCookie = (upstream.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  const cookies = typeof getSetCookie === 'function' ? getSetCookie.call(upstream.headers) : [];
  for (const cookie of cookies) {
    res.append('Set-Cookie', cookie);
  }
}

const app = express();
app.set('trust proxy', 1);

/** UI routes: backend returns view JSON; this process renders EJS. */
app.use(async (req, res, next) => {
  if (!isUiPath(req.path) || req.method === 'OPTIONS') {
    next();
    return;
  }

  try {
    const rawBody = ['GET', 'HEAD'].includes(req.method) ? undefined : await readRequestBody(req);
    const body = rawBody ? new Uint8Array(rawBody) : undefined;
    const skip = hopByHopHeaders();
    const headers: Record<string, string> = {
      'x-sso-ui': '1',
      accept: `${SSO_VIEW_CONTENT_TYPE}, text/html;q=0.8, */*;q=0.5`,
      'x-forwarded-host': req.headers.host ?? `localhost:${PORT}`,
      'x-forwarded-proto': req.protocol || 'http',
    };

    for (const [key, value] of Object.entries(req.headers)) {
      if (value === undefined || skip.has(key.toLowerCase())) continue;
      if (key.toLowerCase() === 'accept') continue;
      headers[key] = Array.isArray(value) ? value.join(',') : value;
    }

    const upstream = await fetch(`${BACKEND}${req.originalUrl}`, {
      method: req.method,
      headers,
      body,
      redirect: 'manual',
    });

    forwardSetCookies(upstream, res);

    const requestId = upstream.headers.get('x-request-id');
    if (requestId) res.setHeader('x-request-id', requestId);

    const cacheControl = upstream.headers.get('cache-control');
    if (cacheControl) res.setHeader('cache-control', cacheControl);

    if (upstream.status >= 300 && upstream.status < 400) {
      const location = upstream.headers.get('location') ?? '/';
      res.redirect(upstream.status as 301 | 302 | 303 | 307 | 308, location);
      return;
    }

    const contentType = upstream.headers.get('content-type') ?? '';
    if (contentType.includes(SSO_VIEW_CONTENT_TYPE)) {
      const payload = (await upstream.json()) as { view?: string; locals?: Record<string, unknown> };
      if (!payload.view) {
        res.status(502).type('html').send('<h1>Invalid view model from SSO backend</h1>');
        return;
      }
      const file = path.join(VIEWS_DIR, `${payload.view}.ejs`);
      // Sync includes (<%- include('head') %>) — do not enable async:true or
      // includes become Promises and render as "[object Promise]".
      const html = (await ejs.renderFile(file, payload.locals ?? {})) as string;
      res.status(upstream.status).type('html').send(html);
      return;
    }

    const buf = Buffer.from(await upstream.arrayBuffer());
    if (contentType) res.type(contentType);
    res.status(upstream.status).send(buf);
  } catch (err) {
    next(err);
  }
});

/** Protocol / API / health traffic — pure HTTP proxy to the backend. */
app.use(
  createProxyMiddleware({
    target: BACKEND,
    changeOrigin: true,
    ws: true,
    on: {
      proxyReq: (proxyReq, req) => {
        const host = req.headers.host ?? `localhost:${PORT}`;
        proxyReq.setHeader('x-forwarded-host', host);
        proxyReq.setHeader('x-forwarded-proto', req.protocol || 'http');
        const requestId = req.headers['x-request-id'];
        if (typeof requestId === 'string' && requestId.length > 0 && requestId.length <= 128) {
          proxyReq.setHeader('x-request-id', requestId);
        }
      },
    },
  }),
);

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`\n  Example Corp SSO Frontend`);
  // eslint-disable-next-line no-console
  console.log(`  Browser:   http://localhost:${PORT}`);
  // eslint-disable-next-line no-console
  console.log(`  Backend:   ${BACKEND}`);
  // eslint-disable-next-line no-console
  console.log(`  Views:     ${VIEWS_DIR}`);
});
