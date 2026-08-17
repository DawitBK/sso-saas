# Example Corp SSO — The Full Story (Build Session Log)

> A comprehensive, detailed record of the engagement that turned the `IdP/` project into a
> real central OIDC single-sign-on system across three standalone apps — the IdP, DMS/EDAMS,
> and GMS (Guest/Visitor Management) — and integrated them without breaking public/guest
> access or touching GMS's auth code.
>
> Written to the repo root because the VS Code extension has no session export. This is a
> faithful, detailed reconstruction of what was decided, built, discovered, broken, and fixed
> — in order — not a verbatim chat transcript (the harness exposes no raw-transcript export).
> Model: Claude **Fable 5** (`claude-fable-5`).
>
> Companion docs: `SSO-ARCHITECTURE.md` (the "why"), `SSO-INTEGRATION-GUIDE.md` (how future
> apps fit in), `SSO-OPERATIONS.md` (run/deploy), and `IdP/identity/README.md`.

---

## Part 1 — The ask

The brief: the `IdP/` project was supposed to be "a gateway, a router, an authentication
provider — SSO with OIDC." The concrete goals:
- **Integrate the IdP with DMS** as a proper OIDC relying party.
- **Use the IdP on GMS by bypassing GMS's built-in auth without touching it** — "just bypass it."
- **SSO for all future apps**, explicitly including **old systems written in PHP and plain JS**
  (the org chose to self-host OAuth 2.0 rather than a third-party vendor, so it must integrate
  broadly, not just Node).
- **Three standalone apps**, each with its own backend, frontend, and **database — no shared DB**.

Later refinements from the user, folded into the design:
- GMS is not entirely internal — **guests** must reach their part with **no SSO**.
- DMS has **non-staff document signing** and **incoming/outgoing letter correspondence** — not
  every endpoint should require IdP login.
- Avoid microservices complexity if possible.
- The frontend experience matters — don't build "only an API gateway" and forget the UX.
- Document everything (architecture, integration, run, deploy) in the repo root.

---

## Part 2 — What the three systems actually looked like (exploration)

Three parallel explorations mapped the ground truth:

**IdP (`IdP/identity/`)** — a **throwaway scaffold**: Express 5 + `jose`, a hand-rolled
`/authorize` + `/token` flow, in-memory stores, an ephemeral RS256 key regenerated on every
boot, no session cookie, no DB, and **no gateway/router at all**. But `docs/idp/` contained a
mature spec (BRD/FRD/TDD) prescribing a production build on the `oidc-provider` (Panva) library
+ Postgres. Three clients were pre-registered in the scaffold: `edams`, `gms`, `retail-os`.

**DMS/EDAMS (`DMS 10/`)** — already **OIDC-ready by design**: a full `/auth/oidc/authorize` +
`/auth/callback` implementation existed in `backend/src/modules/auth/auth.routes.ts`, and the
verify middleware would consume external RS256 tokens the moment `AUTH_ISSUER`/`AUTH_JWKS_URI`/
`AUTH_AUDIENCE` were set. It expected an AD-groups claim `https://edams.examplecorp.com/ad_groups`
and mapped it via an `idp_role_mappings` table. Gaps: a missing `external_sub` column (the
callback wrote it, but the model/column didn't exist) and no "Sign in with SSO" frontend entry.

**GMS (`GMS RELEASE V3/`)** — the bypass lever: its middleware does plain
`jwt.verify(token, JWT_SECRET)` — **HS256, no audience/issuer/JWKS checks** — and access tokens
are stateless. So a token signed with GMS's own secret is accepted by every protected route with
zero GMS code changes. The required payload: `{ id (real numeric users.id), email, roles, permissions, office_id?, session_id }`.

---

## Part 3 — The decisions (and why)

Four architectural questions were put to the user; the answers shaped everything:

1. **Topology → hybrid.** Build the OIDC provider + an SSO portal now; add a reverse-proxy
   gateway later, only where actually needed. (It ended up being needed for GMS — see Part 9.)
2. **IdP foundation → rebuild on `oidc-provider` (Panva).** The deciding factor: true cross-app
   SSO requires a persistent session cookie + server-side session store, which the scaffold
   fundamentally lacked. Building that correctly is 80% of adopting the library anyway, and the
   library adds refresh rotation, introspection, revocation, and RP-logout for free.
3. **Identity source → AD-primary with a local Postgres fallback.** Authenticate against AD/LDAP
   when reachable; fall back to a local user store for service/non-AD accounts.
4. **GMS → token bridge (mint HS256), no GMS code changes.**

A later, deeper architectural conversation (prompted by the user's worry about public/guest
access and legacy apps) crystallized the guiding principle:

- **Two identity planes, one deployment — NOT microservices.** Each app stays the modular
  monolith it is. SSO is applied **selectively**: only the internal/staff surface uses the IdP.
  External/public surfaces (GMS guests via native email/OTP, DMS external signers via signed
  links, the public `/letters/verify` route) keep their existing flows and never touch the IdP.
  This was verified in code: GMS `guest` is a first-class native role; DMS `/letters/verify` is
  mounted before auth.
- **OIDC is a wire protocol, not a Node library.** PHP (`jumbojett/openid-connect-php`),
  plain-JS (`oidc-client-ts`), and every other stack integrate as first-class clients by
  verifying the RS256 token against the published JWKS. Self-hosting OIDC is precisely what keeps
  legacy apps integratable — a vendor SDK would be the lock-in.
- **The IdP is an auth server + a real SSO portal + an optional per-app gateway — NOT a
  mandatory reverse-proxy shell and NOT a micro-frontend host.** A shell would fight public
  routes, legacy apps, and deployment decoupling. Each app keeps its own frontend + a login
  redirect; the portal is the hub; the shared session cookie makes hopping seamless.

---

## Part 4 — Environment discovery (and two gotchas)

- Local **PostgreSQL 17** on `localhost:5432`, user `postgres` / password `leadfreak`. Existing
  DBs included `DMS` and `gmsdev`. Created a new **`idp`** database (with `pgcrypto`) — separate,
  so no app shares a DB.
- Ports/DBs settled: **DMS** `4000`/`3000`/`DMS` · **GMS** `5000`/`5001`/`gmsdev` · **IdP**
  `4100`/`idp` · **GMS gateway** `4200` (added later).
- **Gotcha 1 — a machine-wide `DATABASE_URL`** (pointing at a Railway database) was shadowing
  the IdP's local DB. Fixed by loading the IdP's `.env` with `dotenv.config({ override: true })`.
- **Gotcha 2 — GMS's effective secret.** GMS loads `.env` then `.env.development` with
  `override:true`, so the **effective** dev `JWT_SECRET` is the `.env.development` value
  (`replace_with_a_long_random_secret_at_least_32_characters`), not the `.env` value. The
  bridge's `GMS_JWT_SECRET` must equal whatever GMS actually loads at runtime.

---

## Part 5 — Rebuilding the IdP on oidc-provider

The scaffold's hand-rolled flow was replaced with the `oidc-provider` engine, backed by Postgres.
Components built (`IdP/identity/src/`):

- **`config.ts`** — env-driven (issuer, clients incl. a later `portal` client, TTLs, LDAP, GMS
  bridge, gateway). Loads `.env` with `override:true`.
- **`oidc/provider.ts`** — the provider: Postgres adapter, persisted JWKS, claims (with
  `ad_groups` on the `profile` scope), `conformIdTokenClaims:false` (DMS reads claims straight
  from the id_token), introspection/revocation/RP-logout/userinfo enabled.
- **`adapters/postgres.ts`** — a full oidc-provider Adapter over one `oidc_artifacts` table,
  **including the Session** — this is the SSO backbone that survives restarts.
- **`jwks.ts`** — RS256 signing keys **persisted** in `idp_signing_keys` (the scaffold's
  ephemeral key broke verification after any restart).
- **`auth/`** — `ldap.service.ts` (real `ldapts` AD bind), `local-users.ts` (scrypt hashes +
  lockout + AD upsert), `password.ts` (Node `scrypt`, no native build), `account.ts` (the
  AD-primary→local-fallback `authenticateUser` + the `findAccount` hook).
- **`interactions/`** — login router with double-submit CSRF; consent auto-granted for
  first-party clients (added later for seamless hopping).
- **`db/`** — pool, a small SQL migration runner, and a dev seed. Migrations `001_init.sql`
  (oidc artifacts, signing keys, clients, users/groups, entitlements) and `002_gms_bridge.sql`.

**Deviations from the plan, all deliberate:** used `pg` directly instead of Sequelize (leaner —
the adapter is one table); deferred Redis (Postgres persists sessions, so SSO/refresh already
survive restarts); scrypt instead of argon2/bcrypt (no native build on Windows); set the
provider's authorization route to `/authorize` because DMS hardcodes that path; and required
PKCE only for **public** clients so DMS's confidential non-PKCE flow keeps working with no DMS
change (recommendation noted: add PKCE to DMS later and flip to always-on).

**First verification:** a scripted end-to-end auth-code+PKCE flow (`test-scripts/e2e-oidc.mjs`)
drove login → consent → code → token and asserted the id_token claims (`sub` uuid, `email`,
`email_verified:true`, `ad_groups[]`, matching `nonce`). It caught a real bug in my own test
(oidc-provider redirects with **303**, not 302) — fixed the harness, then it passed. Discovery
and JWKS were confirmed correct (PKCE S256, introspection/revocation/RP-logout advertised; JWKS
exposes only the public key).

---

## Part 6 — DMS integration (config + two pre-existing bugs)

DMS was mostly config, plus fixes:
- **`backend/.env`** — added the OIDC block (`AUTH_ISSUER`, `AUTH_JWKS_URI`, `AUTH_AUDIENCE`,
  `OIDC_CLIENT_ID=edams`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_TOKEN_ENDPOINT`).
  Kept `LOCAL_JWT_MOCK=true` → **dual-run**: the id_token is verified via a separate
  `AUTH_JWKS_URI` path, while DMS's own re-issued token keeps using the dev RSA key, so the dev
  mock login AND SSO both work. Flip to `false` at cutover.
- **`external_sub`** — added to the `User` model + migration `20260705000001`; the callback
  already wrote it, so this stopped it being silently dropped.
- **Frontend** — a "Sign in with Example Corp SSO" button + a new `/auth/callback` page +
  `/auth/callback` added to `AuthGuard`'s public paths.

**Two pre-existing DMS bugs, found only by running the real flow end-to-end** (they had never
been exercised):
1. **ioredis vs node-redis syntax.** `redis.set(key, val, { EX })` (node-redis) was silently
   passing `[object Object]` to ioredis; the OIDC state write threw and the whole authorize 500'd.
   Fixed to ioredis's `set(key, val, 'EX', n)` at two call sites (state + logout revocation).
2. **Array binding.** The AD-group→role query used `ANY(:groups)` with Sequelize `replacements`,
   which inlines a JS array as a single string → Postgres `22P02`. Fixed to `ANY($1)` with `bind`.

**Verification (live, full stack):** `test-scripts/dms-sso-test.mjs` drove DMS authorize → IdP
login/consent → code → DMS callback → **200**, user JIT-provisioned `SYSTEM_ADMIN` (mapped from
`EDAMS_Admins`), tenant `examplecorp`, 45 permissions, and `external_sub` persisted as the IdP `sub`.

---

## Part 7 — The GMS token bridge (zero GMS code changes)

Discovered the exact `gmsdev` schema (roles `super_admin`/`admin`/`reception`/`host`/`guest`/…;
partial-unique index on `users.email WHERE deleted_at IS NULL`; `auth_sessions` with an SHA-256
refresh-token hash). Built `src/bridge/gms.ts`:
- **Provision/match** the `gmsdev.users` row by email (with the partial-index `ON CONFLICT`
  predicate) + link `user_roles` from `idp_gms_role_mappings`.
- **Mint** an HS256 token with GMS's own secret and the exact payload GMS expects; also mint a
  refresh token and write a matching `auth_sessions` row (SHA-256 hash) so GMS's `/auth/refresh`
  keeps the session alive.
- Default role `guest` when no mapping matches (not office-scoped → no office needed); `super_admin`
  for `EDAMS_Admins` via the mapping seed.

**Verification (live, against the running GMS backend):** `test-scripts/gms-live-test.ts` minted
a token and called a protected GMS route — `GET /offices` returned **200 with data**, and the
user was provisioned (id 242, super_admin). `/auth/me` returned 401 (it additionally checks the
DB session via the refresh cookie, which a bare API call doesn't send) — an endpoint-specific
check, not the general auth path. **No GMS source changed.**

---

## Part 8 — The frontend question and the Model-A portal

The user pushed on the frontend UX ("how do staff actually get to GMS?"). Answer: the **portal**
is the hub. It was upgraded to **Model A** — an authenticated, personalized home:
- The portal is itself an **OIDC relying party** of the IdP (a `portal` client), so it reuses the
  shared SSO session to learn who's signed in — no extra password if already logged in elsewhere.
- It **greets the user** and shows **only entitled apps** (filtered via `idp_app_entitlements`).
- **Auto-consent for first-party clients** was added so hopping between apps never shows a consent
  screen. Root `/` now redirects to `/portal` (fixing an oidc-provider "unrecognized route" error
  the user hit at `/`).

---

## Part 9 — Proving it in a real browser, and the honest gap

The user asked to see it "in action" via Playwright. No Playwright MCP was connected to the
session, so — being transparent about that — I installed Playwright directly and drove **headless
Chromium** (`test-scripts/browser-clickthrough.mjs`), capturing screenshots at each step.

First run (10/10 checks): DMS login shows the SSO button → click → IdP login → **DMS dashboard**
signed in → open the **portal with no second password**, personalized, entitled tiles. But step 5
was honest and unflattering: clicking "Open GMS" landed on **GMS's own guest-registration page**,
not an authenticated view — because the bridge produced a valid token at the API level, but the
**browser SPA couldn't be auto-logged-in cross-origin** (browsers isolate localStorage per
origin, so an IdP page on `:4100` can't seed the GMS SPA on `:5001`). I did **not** fake it.

**The same-origin gateway (closing the gap).** Built `src/gateway/server.ts` — a reverse proxy
that runs in the IdP process on **`:4200`, served as `http://gms.localtest.me:4200`** (a
non-loopback host that resolves to 127.0.0.1 with no hosts-file edit — necessary because GMS's
dev frontend force-routes its API to `:5000` for literal `localhost` hosts). It:
- proxies the GMS SPA (`/*` → :5001) and its API (`/api/v1` → :5000) and realtime (`/socket.io`
  → :5000) on one origin;
- exposes `/__sso?code=` which redeems a one-time handoff code (from the bridge), **seeds the GMS
  session** into that origin's localStorage + sets the refresh cookie, and redirects to the
  role-appropriate landing (`/admin` for super_admin, `/reception`, `/host`).

The bridge callback was changed to hand off to the gateway via a one-time code instead of
rendering a cross-origin page. After this, the click-through landed on the **authenticated GMS
`/admin` "Control Center" ("Active role: Super Admin", Sign out)** — verified by screenshot.

---

## Part 10 — The login "incident" (nothing was actually broken)

The user reported "wrong credentials" for the sys admin. I did not guess — I verified the exact
code path against the live DB (`verify('demo') → true`) and drove a **live login against the
running IdP** (`test-scripts/live-login.mjs`) which **passed and reached the portal**. The DB
showed `failed_logins = 4`, and that counter **only increments when the email matches but the
password is wrong** — so the email was right; the submitted password wasn't `demo` (classic
browser password-manager autofill / typo). The credentials were always valid:
**`admin@examplecorp.com` / `demo`** at **`http://localhost:4100/`**. The successful login reset
the counter; the account was never locked. The confusing "wrong credentials" screen the user saw
was **GMS's own staff-login page** (external plane), where the bridged user has no GMS password —
resolved by having the gateway land staff directly on their authenticated area.

---

## Part 11 — The GMS data-fetch failures (CORS) and the fix

With SSO into GMS working, some admin panels failed to load; the Network tab showed **CORS
errors** on `notifications`, `dashboard`, and `integration-health` XHRs. Root cause: GMS's
`.env.development` hardcodes `NEXT_PUBLIC_API_BASE_URL=http://localhost:5000/api/v1`, which
overrode the gateway origin — so on `gms.localtest.me:4200` the SPA was calling `localhost:5000`
**cross-origin**. Fix (no auth code touched):
- Added a GMS-frontend **`.env.local`** (the loader reads it last, with override; it's the
  standard local-override, and direct `:5001` access is unaffected because loopback-force ignores
  it) pointing `NEXT_PUBLIC_API_BASE_URL` + `NEXT_PUBLIC_SOCKET_URL` at the gateway origin.
- Added a `/socket.io` proxy to the gateway for realtime.

Result (verified, 12/12 in the click-through): **no cross-origin `:5000` calls**, `/offices`
`200` same-origin, and the admin console's Operational queue, Arrival Trends, Alerts, and
Activity feed all load ("Dashboard feed unavailable" gone — panels are simply empty, no seeded
visitor data).

---

## Part 12 — The naming correction and the integration-health 404

- **Naming:** GMS had been labeled "Grain Management" (straight from the scaffold's comment). The
  running console (Offices, Hosts, Guests, Visits, Check-in) is clearly **Guest/Visitor
  Management**. Corrected in `config.ts`, the portal tile, the seeded `idp_clients` row, all docs,
  and memory.
- **`integration-health` 404:** the admin dashboard calls `GET /operations/integration-health`,
  but the GMS backend mounted that same handler (`getIntegrationHealth`) at
  `/operations/integrations` — pure path drift. Fixed by adding an **additive alias route**
  `/operations/integration-health` on the GMS backend (the existing `/integrations` route and all
  behavior unchanged). Verified **200** both directly and through the gateway.

---

## Part 13 — Final verified state

Browser click-through (headless Chromium, `test-scripts/browser-clickthrough.mjs`) — **12/12**,
screenshots in `IdP/identity/test-scripts/screenshots/`:
1. DMS login shows the SSO button.
2. Clicking it → the IdP login screen.
3. Credentials → **DMS dashboard**, signed in as `admin@examplecorp.com`.
4. IdP **portal** opens with **no second password**, greets "System Administrator", shows entitled
   EDAMS + GMS tiles.
5. "Open GMS" → bridge → gateway → authenticated **GMS `/admin` console**; session seeded on the
   gateway origin; same-origin GMS API returns 200; **no cross-origin `:5000` calls**.

Supporting harnesses (`IdP/identity/test-scripts/`): `e2e-oidc.mjs`, `bridge-test.ts`,
`gms-live-test.ts`, `dms-sso-test.mjs`, `live-login.mjs`.

---

## Part 14 — Honest caveats & follow-ups

- **Only Node/Next apps were exercised.** OIDC is language-universal (see the integration guide's
  PHP/plain-JS templates); the first legacy onboarding should be piloted end to end.
- **The GMS same-origin requirement** (gateway host + `.env.local`) exists because we refuse to
  touch GMS. An app we control needs none of this — it's a plain OIDC client.
- **Scale/hardening:** Redis for multi-instance sessions, JWKS key rotation, MFA for AD accounts
  (local-store lockout already implemented), and moving the in-memory handoff/gateway/portal
  session stores to Postgres/Redis.
- **"Didn't touch GMS's auth"** is the requirement being met, not a gap. The only GMS-side
  artifacts are DB provisioning (the bridge), a frontend `.env.local` (config), and one additive
  non-auth alias route (the integration-health fix the user explicitly requested).

---

## Part 15 — File inventory

**IdP (`IdP/identity/`) — built:** `src/config.ts`, `src/main.ts`, `src/oidc/{provider,clients}.ts`,
`src/adapters/postgres.ts`, `src/jwks.ts`, `src/auth/{ldap.service,local-users,password,account}.ts`,
`src/interactions/{router,csrf}.ts`, `src/bridge/{gms,router,session}.ts`,
`src/gateway/{server,router}.ts`, `src/portal/{router,session}.ts`, `src/db/{pool,migrate,seed-dev}.ts`,
`migrations/{001_init,002_gms_bridge}.sql`, `views/*.ejs`, `.env`/`.env.example`, `README.md`,
`test-scripts/*`.

**DMS (`DMS 10/`) — changed:** `backend/.env` (OIDC block); `backend/src/.../models/User.ts` +
`backend/migrations/20260705000001-user-external-sub.sql`; `backend/src/modules/auth/auth.routes.ts`
(two redis/array-bind bug fixes); `frontend/app/(auth)/login/page.tsx`,
`frontend/app/auth/callback/page.tsx`, `frontend/shared/components/AuthGuard.tsx`.

**GMS (`GMS RELEASE V3/`) — minimal, non-auth:** `frontend/.env.local` (gateway API/socket base);
`backend/src/modules/operations/operations.routes.ts` (additive `/integration-health` alias).
**No GMS auth code touched.**

**Root docs:** `SSO-ARCHITECTURE.md`, `SSO-INTEGRATION-GUIDE.md`, `SSO-OPERATIONS.md`, this file.

---

## Part 16 — How to run (summary)

Full detail in `SSO-OPERATIONS.md`. Short version: start the IdP (`IdP/identity` → `npm run dev`,
which also starts the gateway on `:4200`), DMS backend + frontend, GMS backend, and the GMS
frontend. Open **`http://localhost:4100/`**, sign in **`admin@examplecorp.com` / `demo`**, and
launch apps from the portal. To add the next app, follow `SSO-INTEGRATION-GUIDE.md` (Mode A for
anything you can give a login redirect — Node/PHP/JS/etc.; Mode B for untouchable legacy).
