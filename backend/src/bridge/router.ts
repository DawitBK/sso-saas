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
import { mintGmsSession, revokeGmsSessionsByEmail, type BridgeIdentity } from './gms.js';
import { getGatewaySession, putGatewaySession } from './session.js';
import { setWebSession, takeWebSession } from '../db/web-sessions.js';
import { createFlowBinding, flowBindingMatches, flowBindingCookieOptions } from '../auth/flow-binding.js';
import { loadClients } from '../oidc/clients.js';
import { logger } from '../logging/logger.js';

const BIND_COOKIE = 'gms_bridge_bind';
/**
 * Separate from BIND_COOKIE above. That one binds the *handoff* hop (callback →
 * gateway); this one binds the hop before it (start → callback), which is where
 * identity is actually established and therefore where login-CSRF bites. Both
 * are scoped to only the single path that consumes them.
 */
const STATE_BIND_COOKIE = 'gms_bridge_state_bind';

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

/**
 * P2-9 item 2: the client secret comes from `idp_clients`, with the seed value as
 * the fallback.
 *
 * It used to be read only from IDP_CONFIG.clientSeed — i.e. from the environment
 * — so rotating the `gms` client secret in the database (which the admin console
 * can do, and which seedClients() deliberately never overwrites once it is a real
 * value) silently broke the bridge's token exchange: the IdP would reject its own
 * bridge's client_secret_post. Nothing in the failure named the cause.
 *
 * Read lazily and cached per process rather than at module load, because this
 * module is imported before the pool is necessarily usable.
 */
// Cached for a short while only: the console can now rotate this secret, and a process-lifetime cache would keep presenting the old
// one until a restart.
const SECRET_CACHE_MS = 15_000;
let cachedClientSecret: string | null = null;
let cachedAt = 0;
async function resolveClientSecret(): Promise<string> {
  if (cachedClientSecret !== null && Date.now() - cachedAt < SECRET_CACHE_MS) return cachedClientSecret;
  try {
    const clients = await loadClients();
    const fromDb = clients.find((c) => c.client_id === CLIENT_ID)?.client_secret;
    if (typeof fromDb === 'string' && fromDb) {
      cachedClientSecret = fromDb;
      cachedAt = Date.now();
      return cachedClientSecret;
    }
  } catch (err) {
    logger.error({ err }, '[idp:bridge] could not load the gms client secret from idp_clients — falling back to the seeded value');
  }
  cachedClientSecret = IDP_CONFIG.clientSeed.find((c) => c.client_id === CLIENT_ID)?.client_secret ?? '';
  cachedAt = Date.now();
  return cachedClientSecret;
}

interface Pending { verifier: string; nonce: string; bindingHash: string }
const PENDING_TTL_MS = 10 * 60_000;
const STATE_BIND_PATH = `${IDP_CONFIG.publicBasePath}/bridge/gms/callback`;

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function gmsBridgeRouter(): Router {
  const router = Router();

  router.get('/gms/start', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      if (!IDP_CONFIG.gms.enabled) return res.status(503).render('error', { message: 'GMS bridge is disabled.' });
      const verifier = base64url(crypto.randomBytes(32));
      const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
      const state = base64url(crypto.randomBytes(16));
      const nonce = base64url(crypto.randomBytes(16));
      // See auth/flow-binding.ts: `state` alone does not identify the browser,
      // so a code+state pair from the attacker's own completed authorization
      // could be replayed into a victim's browser to sign them in as the
      // attacker — and here that mints a real GMS session, not just a portal one.
      const binding = createFlowBinding();
      await setWebSession('pending_gms', state, { verifier, nonce, bindingHash: binding.hash } satisfies Pending, PENDING_TTL_MS);
      res.cookie(STATE_BIND_COOKIE, binding.token, flowBindingCookieOptions(STATE_BIND_PATH, PENDING_TTL_MS, IDP_CONFIG.isProd));

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        // ad_groups + gms_roles are now separate scopes (P1-2) — without asking
        // for them the id_token carries no groups and mintGmsSession would fall
        // back to whatever its no-groups path yields.
        scope: 'openid profile email ad_groups gms_roles',
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
      // Path must match /gms/start's res.cookie() exactly or this is a no-op.
      res.clearCookie(STATE_BIND_COOKIE, { path: STATE_BIND_PATH });
      if (!code || !flow) return res.status(400).render('error', { message: 'Invalid or expired bridge state.' });
      if (!flowBindingMatches(cookieValue(req, STATE_BIND_COOKIE), flow.bindingHash)) {
        return res.status(400).render('error', {
          message: 'This GMS sign-in was started in a different browser or has expired — go back to the portal and try again.',
        });
      }

      // Exchange the code (client_secret_post + PKCE verifier).
      const tokenRes = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          client_secret: await resolveClientSecret(),
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
        // Pin the algorithm rather than accepting whatever the JWKS offers.
        // Only RS256 keys are ever published today (jwks.ts), so this changes
        // nothing now and prevents an unexpected alg being honoured if another
        // key type is ever added to the set.
        algorithms: ['RS256'],
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
      let handoffCode: string;
      try {
        handoffCode = await putGatewaySession({
          gmsAccessToken: session.accessToken,
          gmsRefreshToken: session.refreshToken,
          userId: session.userId,
          roles: session.roles,
          officeId: session.officeId,
          email: identity.email.toLowerCase(),
          bindingHash,
        });
      } catch (handoffErr) {
        // mintGmsSession above already caused GMS to mint a real, live session
        // (write #1, already committed by the time control returned). If our
        // own handoff-record write (write #2) fails, that GMS session is
        // orphaned — nobody will ever redeem it — unless we compensate here.
        // Best-effort: a failure to revoke must not mask or replace the
        // original handoff error being surfaced to the caller below.
        try {
          await revokeGmsSessionsByEmail(identity.email);
        } catch (revokeErr) {
          logger.error(
            { err: revokeErr, email: identity.email },
            '[idp:bridge] failed to compensate an orphaned GMS session after putGatewaySession failed',
          );
        }
        throw handoffErr;
      }
      // Prefixed with publicBasePath — under /sso the console is served at /sso/admin, so the cookie path needs the public base path.
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
