# Example Corp SSO — Env Vars and Working Auth Code

Companion to `SSO-INTEGRATION-GUIDE.md`. That doc explains the concepts;
this one gives exact env values and working code you can adapt directly.

## Contents

1. [Register your client](#1-register-your-client)
2. [Environment variables](#2-environment-variables)
3. [Mode A — full working code](#3-mode-a--full-working-code)
4. [Mode B — token bridge + gateway](#4-mode-b--token-bridge--gateway-legacy-no-touch-apps)
5. [Mode C — additional login option](#5-mode-c--additional-login-option-keep-local-accounts)
6. [Role mapping code](#6-role-mapping-code)
7. [Backchannel logout code](#7-backchannel-logout-code)
8. [Security checklist](#8-security-checklist)

---

## 1. Register your client

Ask the IdP administrator to add your app, or add it yourself if you run
the IdP. This is a config change on the IdP side, not a database insert —
give them (or set) these exact values:

```
client_id:                  myapp
client_secret:               <generate: openssl rand -hex 32>
redirect_uris:                http://localhost:7101/auth/callback   (dev)
                               https://myapp.yourdomain.com/auth/callback (prod)
post_logout_redirect_uris:    http://localhost:7101/login (dev)
                               https://myapp.yourdomain.com/login (prod)
name:                         My App
```

`client_id` is permanent once anything references it — don't rename it later.

## 2. Environment variables

**Your app's backend `.env` (dev):**

```env
AUTH_ISSUER=http://localhost:7301
AUTH_INTERNAL_URL=http://localhost:7300
AUTH_JWKS_URI=http://localhost:7300/jwks
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=myapp-dev-secret
OIDC_REDIRECT_URI=http://localhost:7101/auth/callback
OIDC_TOKEN_ENDPOINT=http://localhost:7300/token
OIDC_SCOPES=openid profile email
OIDC_POST_LOGOUT_REDIRECT_URI=http://localhost:7101/login
```

**Your app's backend `.env.production`:**

```env
AUTH_ISSUER=https://sso.yourdomain.com
AUTH_INTERNAL_URL=http://127.0.0.1:7300
AUTH_JWKS_URI=http://127.0.0.1:7300/jwks
OIDC_CLIENT_ID=myapp
OIDC_CLIENT_SECRET=<the real generated secret from step 1 — never commit this>
OIDC_REDIRECT_URI=https://myapp.yourdomain.com/auth/callback
OIDC_TOKEN_ENDPOINT=http://127.0.0.1:7300/token
OIDC_SCOPES=openid profile email
OIDC_POST_LOGOUT_REDIRECT_URI=https://myapp.yourdomain.com/login
```

`AUTH_INTERNAL_URL`/`AUTH_JWKS_URI`/`OIDC_TOKEN_ENDPOINT` point at the
loopback address only if your app runs on the same host as the IdP
behind the same reverse proxy. If it runs elsewhere, point these at
whatever address actually reaches the IdP backend from your app's server
— just don't route server-to-server calls back out through a public load
balancer if you don't have to.

Never use an `http://localhost` value in any of these in production —
the redirect URI in particular must exactly match what's registered on
the IdP side in step 1, including scheme and trailing slash.

## 3. Mode A — full working code

Node/Express, using `jose` for JWKS verification (`npm i jose`). Adapt the
storage of `pending` (currently in-memory) to Redis or a DB table in
production — an in-memory `Map` does not survive a restart or work across
multiple app instances.

```js
// auth.routes.js
import { Router } from 'express';
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const {
  AUTH_ISSUER,
  AUTH_INTERNAL_URL,
  AUTH_JWKS_URI,
  OIDC_CLIENT_ID,
  OIDC_CLIENT_SECRET,
  OIDC_REDIRECT_URI,
  OIDC_SCOPES,
} = process.env;

const JWKS = createRemoteJWKSet(new URL(AUTH_JWKS_URI));

// Replace with Redis/DB in production — state must survive across instances.
const pending = new Map(); // state -> { nonce, expiresAt }
const PENDING_TTL_MS = 10 * 60_000;

export const authRoutes = Router();

// Step 1: redirect the browser to the IdP.
authRoutes.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  pending.set(state, { nonce, expiresAt: Date.now() + PENDING_TTL_MS });

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: OIDC_CLIENT_ID,
    redirect_uri: OIDC_REDIRECT_URI,
    scope: OIDC_SCOPES || 'openid profile email',
    state,
    nonce,
  });
  res.redirect(`${AUTH_ISSUER}/authorize?${params.toString()}`);
});

// Step 2: handle the callback, exchange the code, verify the token.
authRoutes.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  const flow = pending.get(state);
  pending.delete(state); // single-use, whether or not it's valid

  if (!code || !state || !flow || flow.expiresAt < Date.now()) {
    return res.status(400).send('Invalid or expired login attempt.');
  }

  const tokenRes = await fetch(`${AUTH_INTERNAL_URL}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: OIDC_REDIRECT_URI,
      client_id: OIDC_CLIENT_ID,
      client_secret: OIDC_CLIENT_SECRET,
    }),
  });
  if (!tokenRes.ok) {
    return res.status(502).send('Token exchange failed: ' + (await tokenRes.text()));
  }
  const { id_token } = await tokenRes.json();
  if (!id_token) return res.status(502).send('IdP did not return an id_token.');

  let claims;
  try {
    ({ payload: claims } = await jwtVerify(id_token, JWKS, {
      issuer: AUTH_ISSUER,
      audience: OIDC_CLIENT_ID,
    }));
  } catch {
    return res.status(401).send('id_token failed signature/issuer/audience verification.');
  }

  if (claims.nonce !== flow.nonce) {
    return res.status(400).send('Nonce mismatch — possible replay attack.');
  }
  if (claims.email_verified !== true) {
    return res.status(403).send('Identity provider has not verified this email.');
  }

  const email = String(claims.email);
  const groups = claims['https://myapp.yourdomain.com/ad_groups'] ?? [];

  // ---- App-specific from here ----
  // 1. Find or create the local user by `email`.
  //    New users: unusable random local password, default role.
  // 2. Map `groups` to your app's own roles (see §6).
  // 3. Issue YOUR app's own session/JWT/cookie — the same function your
  //    normal local-login path already calls.
  //
  // const user = await findOrCreateUser(email);
  // const roles = mapGroupsToRoles(groups);
  // issueAppSession(res, user, roles);

  res.redirect('/');
});
```

That's the entire server-side contract in any language: redirect to
`/authorize`, `POST` to `/token`, verify against `/jwks`, check
`nonce`/`email_verified`. A PHP, Python, or .NET app does the identical
four steps with that language's own HTTP client and JWT library.

## 4. Mode B — token bridge + gateway (legacy, no-touch apps)

Zero changes to the target app. Three pieces, built on the IdP side:

1. **Bridge module.** Connects to the target app's own DB/store, finds
   or provisions its user record, and mints whatever credential that app
   already trusts (its own JWT format, session row, signed cookie).
2. **OIDC flow run on the app's behalf.** A `/bridge/<app>/start` +
   `/bridge/<app>/callback` pair — identical to the Mode A code in §3,
   but with PKCE added (`code_challenge`/`code_challenge_method=S256` on
   the authorize request, `code_verifier` on the token exchange) since
   this is a service acting on the user's behalf. On success it calls the
   bridge module, then issues a single-use, cookie-bound handoff code
   (bind it to an httpOnly cookie set on this same request, so a leaked
   code alone can't be redeemed by a different browser).
3. **Same-origin gateway.** A reverse proxy serving the target app's
   frontend + API on one origin, with one endpoint that redeems the
   handoff code and seeds the session the way the app expects (cookie or
   `localStorage`), then redirects into the app. Point the app's frontend
   config (not its code) at this origin so its API calls become
   same-origin.

## 5. Mode C — additional login option (keep local accounts)

Identical routes to §3, with one change at the end of the callback:
instead of building new session logic, upsert the local user by email
(random unusable password if the schema needs one) and call the exact
function your existing local-login route already calls to issue a
session/token. Nothing else in the app changes.

## 6. Role mapping code

Two options, pick one:

**A — you resolve it.** Read the `ad_groups` claim, look up your own
group→role table, apply this precedence: explicit per-user override →
group mapping → hardcoded default role. Never hard-fail a login just
because a group has no mapping — fall through to the default.

```js
async function mapGroupsToRoles(groups) {
  if (groups.length === 0) return ['EMPLOYEE'];
  const rows = await db.query(
    'SELECT role_name FROM app_role_mappings WHERE group_dn = ANY($1)',
    [groups],
  );
  return rows.length ? rows.map(r => r.role_name) : ['EMPLOYEE'];
}
```

**B — the IdP resolves it for you.** Ask the IdP administrator to add an
app-specific roles claim (e.g. `https://myapp.yourdomain.com/roles`) that
the IdP computes and places in the id_token, so you read it directly off
`claims['https://myapp.yourdomain.com/roles']` instead of maintaining
your own mapping table.

Either way: this is a coarse role signal only. Fine-grained permissions
inside your app are always your app's own responsibility.

## 7. Backchannel logout code

Register a backchannel-logout URL with the IdP. It receives a signed
logout token whenever a user signs out at the IdP or is disabled.

```js
authRoutes.post('/auth/backchannel-logout', express.urlencoded({ extended: false }), async (req, res) => {
  const logoutToken = req.body.logout_token;
  if (!logoutToken) return res.status(400).send('logout_token required');

  let claims;
  try {
    ({ payload: claims } = await jwtVerify(logoutToken, JWKS, {
      issuer: AUTH_ISSUER,
      audience: OIDC_CLIENT_ID,
    }));
  } catch {
    return res.status(400).send('invalid logout token');
  }

  const events = claims.events || {};
  if (!events['http://schemas.openid.net/event/backchannel-logout'] || claims.nonce) {
    return res.status(400).send('not a valid logout token');
  }

  // Resolve claims.sub -> your local user, then set a revocation cutoff
  // (e.g. in Redis: revoked_user:<userId> = now, TTL longer than any token
  // lifetime you issue). Every access/refresh token issued at or before
  // that cutoff must be rejected on next use.
  // await setRevocationCutoff(claims.sub, Date.now());

  res.json({ ok: true }); // always 200, even for an unknown subject
});
```

## 8. Security checklist

- Verify `iss`, `aud`, and token expiry on every token — not just the signature.
- `email_verified !== true` → reject. Treat a missing field as unverified.
- `state` is single-use CSRF protection; `nonce` is single-use replay protection. Delete both on first use.
- Public/browser-only clients (`token_endpoint_auth_method: none`) are **not supported** by this IdP (every client is `client_secret_post`, `oidc/clients.ts`); put a server-side component holding the secret in front of such an app. Send PKCE regardless.
- `client_secret` lives only in environment config — never commit it.
- Production redirect URIs and secrets must never be `localhost`/dev defaults — the exact values from §1/§2, not placeholders.
