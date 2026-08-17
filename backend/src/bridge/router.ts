/**
 * GMS bridge router. Acts as an OIDC relying party against THIS IdP for the
 * `gms` client, so it transparently reuses the SSO session (no second login).
 * On callback it mints a GMS-compatible session (see gms.ts) and hands off to
 * the GMS SPA.
 *
 * Flow:
 *   /bridge/gms/start   → authorization_code + PKCE redirect to our own /auth
 *   /bridge/gms/callback→ token exchange, verify id_token, mint GMS session,
 *                          store it for the gateway relay, render handoff page.
 *
 * Cross-origin note (dev): the IdP origin cannot write the GMS SPA's localStorage
 * directly. Full seamless SPA handoff is delivered by the same-origin gateway
 * (see gateway/). The minted token is always valid at the GMS API (verifiable
 * with a Bearer call), which proves the bypass.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import crypto from 'node:crypto';
import { AD_GROUPS_CLAIM, IDP_CONFIG } from '../config.js';
import { mintGmsSession, type BridgeIdentity } from './gms.js';
import { getGatewaySession, putGatewaySession } from './session.js';
import { setWebSession, takeWebSession } from '../db/web-sessions.js';

const BIND_COOKIE = 'gms_bridge_bind';

function cookieValue(req: Request, name: string): string | undefined {
  const h = req.headers.cookie;
  if (!h) return undefined;
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return undefined;
}

const CLIENT_ID = 'gms';
const ISS = IDP_CONFIG.issuer.replace(/\/$/, '');
const INTERNAL = IDP_CONFIG.internalUrl.replace(/\/$/, '');
const REDIRECT_URI = `${ISS}/bridge/gms/callback`;
const AUTH_ENDPOINT = `${ISS}/authorize`;
const TOKEN_ENDPOINT = `${INTERNAL}/token`;
const JWKS = createRemoteJWKSet(new URL(`${INTERNAL}/jwks`));

const clientSecret = IDP_CONFIG.clientSeed.find((c) => c.client_id === CLIENT_ID)?.client_secret ?? '';

interface Pending { verifier: string; nonce: string }
const PENDING_TTL_MS = 10 * 60_000;

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function gmsBridgeRouter(): Router {
  const router = Router();

  router.get('/gms/start', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!IDP_CONFIG.gms.enabled) return res.status(503).render('error', { message: 'GMS bridge is disabled.' });
      const verifier = base64url(crypto.randomBytes(32));
      const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
      const state = base64url(crypto.randomBytes(16));
      const nonce = base64url(crypto.randomBytes(16));
      await setWebSession('pending_gms', state, { verifier, nonce } satisfies Pending, PENDING_TTL_MS);

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile email',
        state,
        nonce,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
      res.redirect(`${AUTH_ENDPOINT}?${params.toString()}`);
    } catch (err) { next(err); }
  });

  router.get('/gms/callback', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const code = String(req.query.code ?? '');
      const state = String(req.query.state ?? '');
      const flow = await takeWebSession<Pending>('pending_gms', state);
      if (!code || !flow) return res.status(400).render('error', { message: 'Invalid or expired bridge state.' });

      // Exchange the code (client_secret_post + PKCE verifier).
      const tokenRes = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          client_secret: clientSecret,
          code_verifier: flow.verifier,
        }).toString(),
      });
      if (!tokenRes.ok) {
        const body = await tokenRes.text().catch(() => '');
        return res.status(502).render('error', { message: 'Token exchange failed.', detail: body.slice(0, 200) });
      }
      const tokens = (await tokenRes.json()) as { id_token?: string };
      if (!tokens.id_token) return res.status(502).render('error', { message: 'IdP did not return an id_token.' });

      // Verify the id_token against our own JWKS + nonce.
      const { payload } = await jwtVerify(tokens.id_token, JWKS, {
        issuer: IDP_CONFIG.issuer,
        audience: CLIENT_ID,
      });
      if (payload.nonce !== flow.nonce) return res.status(400).render('error', { message: 'Nonce mismatch (possible replay).' });

      const identity: BridgeIdentity = {
        email: String(payload.email ?? ''),
        givenName: String(payload.given_name ?? ''),
        familyName: String(payload.family_name ?? ''),
        groups: (payload[AD_GROUPS_CLAIM] as string[] | undefined) ?? [],
      };
      if (!identity.email) return res.status(400).render('error', { message: 'id_token missing email claim.' });

      const session = await mintGmsSession(identity, String(res.locals.requestId ?? ''));

      // Hand off to the same-origin gateway via a one-time code, but bind it
      // first: an httpOnly cookie set here (this origin) carries a token whose
      // hash is stored alongside the code, and /bridge/gms/handoff below — the
      // next hop, still on this origin — checks the cookie before forwarding the
      // browser on to the gateway. A code alone (leaked via a log line, a proxy,
      // a link-scanner prefetch) can no longer be redeemed by anyone but the
      // browser that actually completed this callback.
      const bindingToken = crypto.randomBytes(32).toString('hex');
      const bindingHash = crypto.createHash('sha256').update(bindingToken).digest('hex');
      const handoffCode = await putGatewaySession({
        gmsAccessToken: session.accessToken,
        gmsRefreshToken: session.refreshToken,
        userId: session.userId,
        roles: session.roles,
        officeId: session.officeId,
        email: identity.email.toLowerCase(),
        bindingHash,
      });
      // Prefixed with publicBasePath — see the matching note in admin/csrf.ts.
      res.cookie(BIND_COOKIE, bindingToken, {
        httpOnly: true,
        sameSite: 'lax',
        secure: IDP_CONFIG.isProd,
        path: `${IDP_CONFIG.publicBasePath}/bridge/gms/handoff`,
        maxAge: 2 * 60_000,
      });
      res.set('cache-control', 'no-store');
      res.redirect(`/bridge/gms/handoff?code=${encodeURIComponent(handoffCode)}`);
    } catch (err) {
      next(err);
    }
  });

  // Same-origin confirmation hop: only a request carrying the binding cookie
  // set just above (i.e. the actual browser from the callback) is forwarded on
  // to the gateway's one-time redemption endpoint.
  router.get('/gms/handoff', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const code = String(req.query.code ?? '');
      const bindingToken = cookieValue(req, BIND_COOKIE);
      // Path must match the res.cookie() call above exactly, or clearCookie
      // silently fails to remove it (Express/the browser only clear a cookie
      // whose Path attribute matches what's given here).
      res.clearCookie(BIND_COOKIE, { path: `${IDP_CONFIG.publicBasePath}/bridge/gms/handoff` });

      const pending = await getGatewaySession(code);
      const presentedHash = bindingToken ? crypto.createHash('sha256').update(bindingToken).digest('hex') : '';
      if (!pending || !bindingToken || presentedHash !== pending.bindingHash) {
        res.status(400).render('error', {
          message: 'This GMS sign-in link is invalid, expired, or was opened in a different browser — go back to the portal and try again.',
        });
        return;
      }
      res.set('cache-control', 'no-store');
      res.redirect(`${IDP_CONFIG.gateway.publicUrl}/__sso?code=${encodeURIComponent(code)}`);
    } catch (err) {
      next(err);
    }
  });

  return router;
}
