# Example Corp SSO — Integration Guide

This document tells you everything needed to plug an application into the
Example Corp identity provider (IdP): what SSO gives you, which integration
pattern fits your app, and the exact steps to follow. It is written to be
handed to a developer who has never touched this codebase before and has
no prior context on how other applications integrate.

## Contents

1. [What SSO is](#1-what-sso-is)
2. [Endpoints and claims](#2-endpoints-and-claims)
3. [Pick your integration mode](#3-pick-your-integration-mode)
4. [Step 0 — register your app as an OIDC client](#4-step-0--register-your-app-as-an-oidc-client)
5. [Step 0.5 — add a portal tile](#5-step-05--add-a-portal-tile)
6. [Mode A — real OIDC client](#6-mode-a--real-oidc-client)
7. [Mode B — token bridge + gateway](#7-mode-b--token-bridge--gateway-legacy-no-touch-apps)
8. [Mode C — additional login option](#8-mode-c--additional-login-option-keep-local-accounts)
9. [Role and permission mapping](#9-role-and-permission-mapping)
10. [Backchannel logout](#10-backchannel-logout-recommended)
11. [Security requirements](#11-security-requirements-non-negotiable)
12. [What must stay outside SSO](#12-what-must-stay-outside-sso)
13. [Onboarding checklist](#13-onboarding-checklist)

---

## 1. What SSO is

The IdP is a spec-compliant OpenID Connect provider. One login at the SSO
portal creates a session cookie on the IdP's own origin; every relying
party (your app) gets the user's identity by running the standard
authorization-code flow against that same IdP. If the user already has an
SSO session, this round-trip succeeds silently — no second login prompt.

Two things it explicitly does **not** do:

- It does not decide what a user is allowed to do inside your app. It
  authenticates *who someone is* and optionally hands you a coarse role
  claim; your app still owns its own authorization model.
- It does not touch public or external-facing flows (anything a
  non-employee legitimately uses). Those keep working with zero IdP
  involvement — see [§12](#12-what-must-stay-outside-sso).

## 2. Endpoints and claims

**Issuer / base URL**

| Environment | Issuer (browser-facing) | Internal URL (server-to-server) |
|---|---|---|
| Dev | `http://localhost:7301` | `http://localhost:7300` |
| Prod | your production SSO domain | a loopback/internal address reachable from your app's backend |

Use the **issuer** for anything the browser is redirected to (the
authorize endpoint, the logout page). Use the **internal URL** for calls
your backend makes directly (token exchange, JWKS fetch) — if your app and
the IdP run behind the same reverse proxy on one host, calling back out
through the public issuer for a server-to-server request is unnecessary
extra latency and an unnecessary external dependency.

**OIDC endpoints** (all relative to the issuer):

| Endpoint | Path | Notes |
|---|---|---|
| Discovery | `/.well-known/openid-configuration` | Standard OIDC discovery document — lists every endpoint below |
| Authorization | `/authorize` | Where you redirect the browser to start login |
| Token | `/token` | `client_secret_post` client authentication |
| JWKS | `/jwks` | RS256 signing keys — used to verify tokens, rotates over time |
| Userinfo | `/me` | Optional — every claim is also placed directly in the id_token, so most apps never need to call this |
| RP-initiated logout | `/session/end` | Ends the shared SSO session, not just your app's local one |

You can either hardcode these paths from your own environment config, or
fetch the discovery document at startup and read the endpoint URLs from
it. Both are valid; hardcoding is simpler if you don't need to tolerate
the IdP ever moving its paths.

**Claims present in every id_token** (request scope `openid profile email`):

| Claim | Type | Meaning |
|---|---|---|
| `sub` | string | Stable subject id for the user |
| `email` | string | Use this as the join key to your local user table |
| `email_verified` | boolean | Must be `true` before you trust the email — see [§11](#11-security-requirements-non-negotiable) |
| `name`, `given_name`, `family_name` | string | Display name parts |
| an `ad_groups` claim, namespaced under a fixed URL | string[] | Raw AD group identifiers the user belongs to |

The IdP can also be configured to emit an additional, app-specific coarse
**roles** claim (namespaced under a URL unique to your app) if you'd
rather have the IdP resolve group→role mapping for you instead of doing
it yourself — see [§9](#9-role-and-permission-mapping). Ask the SSO
maintainer for the exact claim name once this is set up for your client,
or add it yourself following the pattern described there.

## 3. Pick your integration mode

Ask one question: **can you add a login redirect and verify a JWT in your
app's own code?**

| | Mode A — OIDC client | Mode B — token bridge + gateway | Mode C — additional login option |
|---|---|---|---|
| Use when | New app, or any app you can modify (any backend language, any SPA framework) | A legacy app you genuinely cannot modify — no way to add a redirect or verify a token | An app with a working local-account login you want to keep, and SSO should just be another way in |
| App code changes | Add "Sign in with SSO" + a callback route; verify id_token against JWKS | None | Small — a new login route + upsert-by-email, reusing existing session/token issuance |
| Who verifies the token | Your app, directly | The IdP, on your app's behalf (mints a credential your app already trusts) | Your app, at the callback, same as Mode A |

Mode A is the default and by far the most common choice — reach for Mode
B only when Mode A is genuinely impossible, and consider Mode C whenever
you have a mature local-auth system you'd rather not disturb.

## 4. Step 0 — register your app as an OIDC client

Before any code runs, your app needs a registered OIDC client on the IdP
side: a `client_id`, a `client_secret`, and the exact redirect URIs
your app will use. Get these from whoever administers the IdP, or if you
administer it yourself, register:

- `client_id` — short, lowercase, stable. Once anything else references
  it (role mappings, entitlements), avoid renaming it — that requires a
  coordinated migration on both sides, not just a config edit.
- `redirect_uris` — the exact callback URL(s) your app will be redirected
  to after login, one per environment you run in. These must match
  **exactly** what your app sends in the authorize request — no trailing
  slash differences, no scheme mismatches.
- `post_logout_redirect_uris` — where the browser lands after signing out.
- `client_secret` — a strong, randomly generated secret, stored only in
  your app's environment configuration, never committed to source
  control and never shared outside the two systems that need it.

**Public clients are not supported by this IdP.** Every client is registered as a
confidential client that authenticates at the token endpoint with
`client_secret_post` (`backend/src/oidc/clients.ts`, `loadClients`); there
is no way to register `token_endpoint_auth_method: none` through configuration.
A browser-only SPA with no backend able to hold a secret therefore cannot be
onboarded as-is: put a small server-side component (a backend-for-frontend) in
front of it that holds the secret and does the code exchange, or ask the IdP
owners to extend `idp_clients` and `loadClients` to support a public client
(a code change, including a nullable secret). PKCE is still sent by every
client and is required for any public client that is ever added.

**Changing addresses later.** The redirect and post-logout addresses are read
from the IdP's environment (`EDAMS_REDIRECT_URIS`, `GMS_REDIRECT_URIS`, ...) only
while the stored secret is still a development default. After that, editing the
environment does not change an existing client: SSO logs an
`[idp:clients:WARN]` line at boot while the stored and configured addresses
differ. Apply the new addresses with `npm run client:uris` (dry run) and
`npm run client:uris -- --apply` in `backend`, then restart SSO.

A production deployment must use real, non-`localhost` redirect URIs and
a real generated secret — never ship a placeholder or development
default to production.

## 5. Step 0.5 — add a portal tile

Registering an OIDC client makes your app **loggable-into**. It does not
automatically make it **visible on an app launcher**, if this IdP serves
one. Those are two separate steps — confirm with whoever runs the IdP
whether a launcher exists and whether your app needs a tile added to it,
and get that tile added at the same time you register the client so the
two don't drift out of sync.

In this IdP the two steps are exactly **two list entries**: the client in
`backend/src/config.ts` (`clientSeed`) and the tile in
`backend/src/portal/catalog.ts` (`APP_REGISTRY`). The admin console's
"App access" list is derived from `APP_REGISTRY`, so it needs no third edit (it
used to be a separate hand-kept list; that was merged on 2026-10-04). An app with
its own roles also needs role code on the IdP side.

Optionally, visibility (or a tile) can be restricted to specific AD groups
rather than shown to every authenticated user — ask the IdP administrator
if you need this and provide the group identifier(s) that should have
access.

## 6. Mode A — real OIDC client

### Flow

```
Browser → GET  /auth/login            (your app)
        → redirect to IdP /authorize  (with state + nonce)
        → user already has an SSO session → IdP redirects straight back
        → GET  your redirect_uri?code=&state=
        → your backend's /auth/callback exchanges code for tokens
        → backend verifies id_token against IdP /jwks
        → backend finds-or-creates the local user by email
        → backend issues your app's own session/JWT, as normal
```

### What your backend must do

1. **Authorize redirect.** Generate a random `state` and `nonce`, store
   them server-side (a cache or a short-lived DB row — anywhere you can
   look them up a moment later), and redirect the browser to
   `{issuer}/authorize` with:
   ```
   response_type=code
   client_id=<your client id>
   redirect_uri=<your registered redirect URI>
   scope=openid profile email
   state=<random value you generated>
   nonce=<random value you generated>
   ```

2. **Token exchange.** On callback, first verify the returned `state`
   matches what you stored (this is your CSRF protection — reject the
   request if it doesn't match or was already consumed). Then `POST` to
   `{internalUrl}/token` with:
   ```
   grant_type=authorization_code
   code=<the code from the callback>
   redirect_uri=<the same redirect URI used above>
   client_id=<your client id>
   client_secret=<your client secret>
   ```

3. **Verify the id_token.** Fetch `{internalUrl}/jwks`, cache the keys
   (refresh the cache once on an unrecognized `kid` before failing — this
   handles the IdP rotating its signing keys without requiring a redeploy
   on your side), and verify:
   - Signature (RS256) against the matching JWK.
   - `iss` equals the IdP's issuer.
   - `aud` equals your `client_id`.
   - `nonce` in the token matches what you stored at authorize time —
     this is what prevents token replay.
   - `email_verified === true` — **do not skip this.** An id_token
     without a verified email must not be trusted for account lookup or
     creation.

4. **Find-or-provision the local user** by `email`. On first login,
   create the local user record with an unusable local password (an
   SSO-provisioned user authenticates via the IdP, never a local
   password) and default them into whatever baseline role/permission set
   new users get in your app.

5. **Resolve roles**, if your app wants coarse roles from SSO rather than
   managing them entirely locally — see [§9](#9-role-and-permission-mapping).

6. **Issue your app's own session/token** exactly the way local login
   already does. From this point on, your app's normal authorization
   logic is completely unaffected — OIDC login is just another way to
   reach the same "user is now authenticated" state your app already
   knows how to handle.

### Any language works

This is standard OIDC — nothing about it requires any particular backend
language or framework. Any OIDC client library (or a hand-rolled
authorize/token/JWKS-verify flow, which is only a few dozen lines) works
identically. The contract is always the same: redirect to `/authorize`,
exchange the code at `/token`, verify against `/jwks`, read `email` +
`email_verified` + whatever role claim you need.

## 7. Mode B — token bridge + gateway (legacy, no-touch apps)

Use this only when Mode A is truly not possible — the app cannot be
given a login redirect, or cannot be taught to verify a JWT. This mode
requires **zero changes to the target app**; all of the work happens on
the IdP side.

### The three pieces

1. **Bridge (mints the app's native credential).** A small service-side
   module connects to the target app's own database (or whatever storage
   it uses for accounts), finds or provisions the app's user record, and
   mints whatever credential that app already trusts and verifies at
   request time — a JWT signed with the app's own secret, a session row
   in its own session store, a signed cookie, whatever it natively
   expects. This is the one piece that requires knowing the target app's
   internals; everything below is generic.

2. **OIDC relying-party flow, run on the app's behalf.** This is a
   standard Mode-A-style OIDC client, registered as its own client id,
   but driven entirely from the IdP side rather than the target app.
   A "start" endpoint redirects to `/authorize` (with PKCE, since this is
   effectively a confidential service acting on the user's behalf); since
   the SSO session is already present it comes straight back; a
   "callback" endpoint verifies the returned id_token and calls the
   bridge module above to mint the app's real credential. The callback
   then hands off a single-use, cookie-bound code — bound so that a
   leaked code (log line, proxy, link-scanner prefetch) cannot be
   redeemed by anyone but the browser that actually completed the login.

3. **Same-origin gateway.** Browsers isolate storage per origin, so the
   IdP cannot hand a session directly to an app hosted on a different
   origin. The gateway is a small reverse proxy that serves the target
   app's frontend *and* proxies its API on one origin. A dedicated
   endpoint on that origin redeems the one-time code from step 2 and
   seeds the session the way the app itself expects (cookie or
   `localStorage`), then redirects into the app's authenticated landing
   page. Point the app's own frontend configuration — not its auth code,
   just wherever it's told which origin to call — at the gateway origin,
   so its API calls become same-origin and need no CORS handling.

If the legacy app can share a parent domain with the IdP in production
and reads its own credential from a cookie scoped to that shared parent
domain, you can sometimes skip the gateway's storage-seeding step
entirely — the gateway's proxy-and-serve role is what's actually
load-bearing; exactly how the session gets seeded adapts to whatever the
app expects.

## 8. Mode C — additional login option (keep local accounts)

This is the mode to reach for when the app already has a working local
login you have no reason to touch, and SSO should simply be *another*
door in. It looks almost exactly like Mode A, with one difference: the
callback does not build a new session/token mechanism — it reuses
whatever local login already produces.

1. A login route that performs the same authorize-redirect as Mode A.
2. A callback route that performs the same token exchange + id_token
   verification as Mode A.
3. **Upsert the local user by email.** If the user doesn't exist locally,
   create them with a random, never-used, never-shown password — it
   exists purely so the row satisfies the same schema local accounts use,
   avoiding a schema change just to support SSO-provisioned users.
4. **Call the exact same token/cookie issuance function local login
   already calls.** Every other part of the app — auth middleware, role
   checks, protected routes — stays completely untouched, because as far
   as the rest of the app is concerned, a normal login just happened.

This mode is deliberately the least invasive: it adds a login path, it
does not touch the authorization model. If the app has no existing
concept of AD-group-derived roles, it's reasonable to give every
SSO-provisioned user a single default local role and worry about
finer-grained mapping later, rather than inventing a mapping table for a
role scheme the app doesn't have yet.

## 9. Role and permission mapping

The IdP authenticates identity; it never decides what a user may do. Two
supported patterns for getting from "who they are" to "what role they
get," in increasing order of shared responsibility:

**A. Resolve the `ad_groups` claim yourself.** Read the raw claim and
look up your own group→role mapping table, owned entirely by your app.
A sensible precedence order: an explicit per-user role assignment first,
group mapping second, a hardcoded default role last — so a login never
hard-fails just because a group mapping is missing or incomplete.

**B. Have the IdP resolve a coarse role claim for you.** The IdP computes
an app-specific roles claim and adds it to the id_token, using the same
precedence as above (explicit per-user grant, then group mapping, then a
default), so every relying party that wants this doesn't have to
duplicate the same mapping logic. Use this when you'd rather the mapping
live in one shared place, or when multiple systems need to agree on the
same coarse role for the same user.

Either is a valid choice for a new integration. If you want option B, ask
the IdP administrator to add your claim (namespaced consistently with any
others already configured) and a mapping table for it; if you'd rather
own it entirely, option A requires nothing from the IdP side beyond the
raw `ad_groups` claim you already get.

Whichever you pick, remember: the claim is a *coarse* signal (a handful
of role names), not a permission system. Fine-grained authorization (who
can edit this specific record) is always the app's own job.

## 10. Backchannel logout (recommended)

If a user is signed out at the IdP, or disabled by an admin, an app that
only checks a locally-cached session will keep honoring that user's
existing token until it naturally expires. Backchannel logout closes that
gap: the IdP POSTs a signed logout token to a URL you register, and your
app immediately invalidates that user's live sessions.

To implement it:

1. Register a backchannel-logout endpoint URL with the IdP.
2. On receipt, verify the logout token against the IdP's JWKS the same
   way you verify an id_token.
3. Confirm the `http://schemas.openid.net/event/backchannel-logout` event
   is present in the token and that `nonce` is **absent** (per spec —
   logout tokens must not carry a nonce).
4. Resolve the token's `sub` claim to your local user and set a
   revocation cutoff — for example, a timestamp stored somewhere fast to
   check (cache or in-memory), longer-lived than any token you issue —
   so every access/refresh token issued at or before that moment is
   rejected on next use.
5. Always respond `200`, regardless of whether the subject is known
   locally — do not leak which users exist by varying your response.

This is optional for a first integration but strongly recommended for
anything holding sensitive data. Without it, "sign the user out" and
"disable this account" at the IdP are not actually enforced anywhere but
the IdP's own portal.

## 11. Security requirements (non-negotiable)

Every mode, every language:

- **Verify `iss`, `aud`, and `exp`** on every token you accept — not just
  signature validity.
- **Check `email_verified === true`** before trusting the email claim for
  account lookup or creation. Treat a missing field as unverified, not as
  verified.
- **Use `state` for CSRF protection** on the authorize round-trip, and
  **`nonce`** to prevent id_token replay. Both are single-use — consume
  and delete them, don't just check-and-leave.
- **Public (no-secret) clients are not supported** by this IdP (every client
  is `client_secret_post`; see section 4). Any client that ever is public must
  perform PKCE; every client here should send it anyway.
- **Never commit a real client secret** to source control. Secrets are
  environment-driven, generated per environment, and never shared outside
  the two systems that need them.
- **HTTPS in production, always.** Development defaults using
  `http://localhost` are never acceptable in a production
  `redirect_uris`/`post_logout_redirect_uris` value.

## 12. What must stay outside SSO

Some routes are legitimately used by people who are not employees and
must keep working with **no IdP involvement at all** — for example:
public registration or booking flows for non-staff users, links sent to
external parties for a one-time action (signing, confirming, verifying
something), and any public verification page meant to be checked by
someone with no account at all.

Rule of thumb: if a legitimate non-employee uses the endpoint, it is
public — do not put it behind SSO.

## 13. Onboarding checklist

**Every mode:**
- [ ] Register an OIDC client with the IdP (client id, secret, exact
      redirect URIs).
- [ ] Confirm whether a portal/launcher tile is needed, and add one.
- [ ] Confirm whether visibility should be restricted to specific groups.
- [ ] Confirm public/guest/external routes still work with no IdP.
- [ ] Use real, non-localhost redirect URIs and a real generated secret
      before any production deploy.

**Mode A additionally:**
- [ ] "Sign in with SSO" entry point + a callback route.
- [ ] Verify `iss`/`aud`/`nonce`/`email_verified` before trusting the token.
- [ ] JIT-provision by email; map `ad_groups` (or a resolved roles claim)
      to your app's own roles.
- [ ] Implement backchannel logout, if the app holds sensitive data.

**Mode B additionally:**
- [ ] A bridge module that provisions the app's user and mints its native
      credential.
- [ ] A group→role mapping table, if the app needs one.
- [ ] Start/callback routes that run the OIDC flow on the app's behalf.
- [ ] A same-origin gateway serving the app's frontend + API + a
      session-seeding endpoint.
- [ ] Point the app's frontend configuration at the gateway origin
      (config only, not auth code).

**Mode C additionally:**
- [ ] SSO login + callback routes alongside the existing local-login
      routes.
- [ ] Upsert-by-email into the existing user table (a random unusable
      password if the schema requires one).
- [ ] Call the app's existing token/session-issuance function — do not
      build a second one.
