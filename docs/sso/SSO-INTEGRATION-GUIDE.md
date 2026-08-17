# Example Corp SSO — Integration Guide

How software plugs into the Example Corp IdP — the two apps live today (DMS, GMS) and,
more importantly, **how to fit future apps into it: brand-new apps, modern stacks, and
old legacy systems (PHP, plain JS) you may or may not be able to modify.** Read
`SSO-ARCHITECTURE.md` for the "why"; `SSO-OPERATIONS.md` for run/deploy.

**Golden rules (apply to every integration):**
1. **Only wire the internal/staff surface.** Public and external-user routes (guest
   login/booking, document-signing links, `/letters/verify`) stay exactly as they are —
   they must keep working with no IdP.
2. **The app keeps owning its roles.** The IdP authenticates *who you are* and emits an
   `ad_groups` claim; each app maps that to its own roles and decides *what you may do*.
3. **Pick the integration mode by one question:** *can the app verify a standard OIDC
   token (or be given a login redirect)?* Yes → Mode A. No / can't touch it → Mode B.

**IdP endpoints** (dev `http://localhost:4100`, prod `https://idp.examplecorp.com`):
`/.well-known/openid-configuration` · `/authorize` · `/token` · `/jwks` · `/me` ·
`/session/end`. The claim contract in every id_token: `sub`, `email`, `email_verified`,
`name`, `given_name`, `family_name`, and `https://edams.examplecorp.com/ad_groups: string[]`.

---

## 1. Three integration modes (choose per app)

| Mode | When to use | App changes | Browser SSO delivery |
|------|-------------|-------------|----------------------|
| **A — OIDC client** | New app, or any app whose login you can edit (Node, React/Vue/Angular SPA, **PHP**, .NET, Java, Python, Go) | Add "Sign in with SSO" + `/auth/callback`; verify the token via JWKS | The app's own frontend + a login redirect |
| **B — Token bridge (+ gateway)** | Legacy app you **cannot** modify (no way to add a redirect or verify a JWT) | **None** in the app | Same-origin gateway serves the app's SPA + injects the minted session |
| **Public / no SSO** | Guests, external signers, public verification | None | N/A — leave native flows alone |

Mode A is the default and by far the simplest. Mode B is the "bypass" — reserved for
systems you truly can't touch (how GMS works today).

---

## 2. Already integrated (current state)

### DMS / EDAMS — Mode A (OIDC client)
- `backend/.env`: `AUTH_ISSUER`, `AUTH_JWKS_URI`, `AUTH_AUDIENCE`, `OIDC_CLIENT_ID=edams`,
  `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI=http://localhost:3000/auth/callback`,
  `OIDC_TOKEN_ENDPOINT`. `LOCAL_JWT_MOCK=true` kept → **dual-run** (dev mock login *and*
  SSO both work; flip to `false` to make SSO the only path).
- Added `external_sub` column (migration `20260705000001`), a "Sign in with Example Corp
  SSO" button, and the `/auth/callback` page.
- On callback DMS JIT-provisions the user by email and maps `ad_groups` → DMS roles via
  the `idp_role_mappings` table.

### GMS — Mode B (token bridge + same-origin gateway), **zero GMS code changes**
GMS = **Guest/Visitor Management**. It verifies HS256 with a shared secret and can't be
modified, so:
- `IdP/identity/src/bridge/gms.ts` provisions a `gmsdev.users` row + `user_roles` and mints
  an HS256 token with GMS's own secret; `src/bridge/router.ts` runs the OIDC dance and hands
  off a one-time code.
- **Same-origin gateway** (`src/gateway/server.ts`, `http://gms.localtest.me:4200`) serves
  the GMS SPA + proxies its `/api/v1` and `/socket.io` on one origin, and seeds the bridged
  session there. A GMS-frontend **`.env.local`** (local override, not auth code) points its
  API/socket at the gateway so calls are same-origin (no CORS). Staff land on `/admin`
  (or `/reception`, `/host`) already signed in; GMS's guest + staff-login pages are untouched.
- `GMS_JWT_SECRET` must equal the secret GMS *actually loads at runtime*.

---

## 3. Mode A — OIDC client (new apps + modifiable legacy)

### A0. Register the app (once, any language)
Insert a client (or add a `clientSeed` entry in `IdP/identity/src/config.ts`), then add a
portal tile and (optionally) entitlements:
```sql
INSERT INTO idp_clients (client_id, client_secret, redirect_uris, post_logout_redirect_uris, name)
VALUES ('myapp', '<strong-secret>', ARRAY['https://myapp.examplecorp.com/auth/callback'],
        ARRAY['https://myapp.examplecorp.com/login'], 'My App');

-- Optional: restrict which groups see the app's portal tile (omit = all staff).
INSERT INTO idp_app_entitlements (relying_party, group_dn)
VALUES ('myapp', 'CN=MyApp_Users,OU=Groups,DC=examplecorp,DC=com');
```
Add a launcher tile in `IdP/identity/src/portal/router.ts` (`catalog()`), and a public
SPA client should register with `token_endpoint_auth_method: 'none'` so the IdP **requires
PKCE** for it.

### A1. PHP (legacy Laravel / plain PHP) — proves the "not Node-only" point
```php
// composer require jumbojett/openid-connect-php
use Jumbojett\OpenIDConnectClient;
$oidc = new OpenIDConnectClient('https://idp.examplecorp.com', 'myapp', '<client-secret>');
$oidc->setRedirectURL('https://myapp.examplecorp.com/auth/callback');
$oidc->addScope(['openid','profile','email']);
$oidc->authenticate();                       // redirect + code exchange + JWT verify (JWKS)
$email  = $oidc->requestUserInfo('email');
$groups = $oidc->getVerifiedClaims('https://edams.examplecorp.com/ad_groups');
// → find/create local user by $email, map $groups to the app's roles, start the app's own session.
```

### A2. Plain-JS SPA (no framework)
```js
// npm i oidc-client-ts  (or hand-roll auth-code + PKCE)
import { UserManager } from 'oidc-client-ts';
const mgr = new UserManager({
  authority: 'https://idp.examplecorp.com', client_id: 'myapp',
  redirect_uri: location.origin + '/auth/callback',
  scope: 'openid profile email', response_type: 'code',   // PKCE auto for public clients
});
// login:            await mgr.signinRedirect();
// on /auth/callback: const u = await mgr.signinRedirectCallback();
//                    u.profile.email, u.profile['https://edams.examplecorp.com/ad_groups']
```

### A3. Node app
Use `openid-client`, or copy DMS's hand-rolled authorize/callback
(`DMS 10/backend/src/modules/auth/auth.routes.ts`). Verify the id_token against `AUTH_JWKS_URI`.

**Backend verification (any language, per request):** verify the RS256 access/id token
against `GET /jwks`, and check `iss`, `aud`, `exp`. That is the entire server-side contract.

---

## 4. Mode B — token bridge + gateway (no-touch legacy)

Use only when you cannot add a redirect or JWT verification to the app. GMS is the reference
implementation; copy it.

**Step 1 — bridge (mint the app's native credential).** Copy `IdP/identity/src/bridge/gms.ts`
→ `bridge/<app>.ts`:
- Connect to the app's own DB and **provision/match its user record** (by email).
- Mint **whatever credential the app already trusts** — an HS256 JWT (GMS), a server session
  row, a signed cookie — matching the app's verifier exactly.
- Add a role-mapping table `idp_<app>_role_mappings` (group_dn → the app's role names).

**Step 2 — OIDC-RP flow.** Copy `src/bridge/router.ts` → `/bridge/<app>/start` +
`/bridge/<app>/callback`. It's an OIDC relying party against our own IdP, so it transparently
reuses the SSO session, then produces a **one-time handoff code**.

**Step 3 — same-origin gateway (how the browser actually logs in).** Copy the pattern in
`src/gateway/server.ts`:
- Serve the app's SPA + proxy its API on **one origin** (a non-loopback host that resolves to
  127.0.0.1 in dev, e.g. `<app>.localtest.me:<port>`; a real subdomain in prod).
- A `/__sso?code=` endpoint redeems the one-time code and **seeds the app's session** into that
  origin (localStorage/cookie as the app expects), then redirects to the app's authenticated
  landing.
- Point the app's frontend at the gateway origin for its API (via the app's own env/config —
  e.g. a `.env.local`, **not** its auth code) so calls are same-origin (no CORS).

**Why the gateway is required:** browsers isolate storage per origin, so an IdP page can't seed
a session into an SPA on a different origin. Serving the SPA through the gateway makes the
seeding same-origin. This is the one place Mode B needs more than the bridge.

**Prod note:** if the legacy app can share a parent domain (`app.examplecorp.com` + the session
cookie on `.examplecorp.com`) and reads its token from that cookie, you can skip the SPA
localStorage seeding. Otherwise use the gateway.

---

## 5. What NOT to touch (external / public surfaces)

Leave these on their existing flows — they must keep working with **no IdP**:
- **GMS guest** registration/booking (email + OTP).
- **DMS external document signing** (signed per-document links).
- **DMS `GET /letters/verify`** and any public QR/verification route.
- Incoming/outgoing letter correspondence recipients who are not staff.

Rule of thumb: if a non-employee legitimately uses an endpoint, it is **external** → do not
put it behind SSO.

---

## 6. Onboarding checklists

**Mode A (OIDC client):**
- [ ] `INSERT` an `idp_clients` row (+ portal tile; optional `idp_app_entitlements`).
- [ ] Add "Sign in with SSO" + `/auth/callback` to the app's frontend.
- [ ] On callback: JIT-provision by email, map `ad_groups` → the app's roles.
- [ ] Verify the token against `/jwks` (`iss`/`aud`/`exp`) on every request.
- [ ] Confirm public/guest routes still work with no IdP.

**Mode B (bridge + gateway):**
- [ ] `bridge/<app>.ts` — provision the app's user + mint its native credential.
- [ ] `idp_<app>_role_mappings` — group → app role.
- [ ] `/bridge/<app>/start` + `/callback` (copy `bridge/router.ts`).
- [ ] Gateway origin serving the SPA + API + `/__sso` handoff (copy `gateway/server.ts`).
- [ ] App frontend env → gateway API base (local override, not auth code).
- [ ] Confirm the app's own login + public flows are untouched.

**Both:** add the app to the `SSO-OPERATIONS.md` service matrix.
