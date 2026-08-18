# Example Corp Identity Provider

Central **OIDC single-sign-on** provider + SSO portal + gateway relay for all Example Corp
apps (DMS/EDAMS, GMS, and future apps). Built on [`oidc-provider`](https://github.com/panva/node-oidc-provider)
(Panva) with a PostgreSQL store.

- **One login, every app.** A persistent SSO session cookie means signing in once covers
  DMS, GMS, and any future relying party.
- **DMS/EDAMS** integrates as a standard OIDC relying party (RS256 + JWKS).
- **GMS** is signed in via a **token bridge** — the IdP performs an OIDC handoff,
  then asks GMS's authenticated internal API to issue the GMS session and
  provision the user if needed.
- **Identity source:** Active Directory (LDAP) primary, with a local Postgres user store
  fallback for non-AD/service accounts.
- **Self-service security (`/portal/security`).** Users manage their own MFA enrollment,
  see and individually revoke their own live sessions, review their recent sign-in activity,
  and — for local-source accounts — change their own password, without needing an admin.
- **Admin visibility into registered OIDC clients (`/admin/clients`).** Read-only list of
  every relying party (EDAMS, GMS, MRS, the portal itself): redirect URIs, grant types,
  active flag. See "OIDC client registry" below for why it's read-only.

## Architecture

```
Browser ──login──▶ SSO frontend (:7301, HTTP proxy)
                    └─▶ SSO backend (:7300, oidc-provider + EJS render)
                    ├─ /                    → /portal (friendly landing)
                    ├─ /.well-known, /authorize, /token, /me, /jwks, /session/end
                    ├─ /interaction/:uid   login (+ auto-consent for first-party)
                    ├─ /portal             authenticated, personalized SSO launcher (Model A)
                    │                       + self-service security (MFA, password, sessions,
                    │                       sign-in history) at /portal/security
                    └─ /bridge/gms/*        GMS token bridge (OIDC RP → mint HS256)

GMS same-origin gateway (same process, :4200, http://gms.localtest.me:4200)
                    ├─ /__sso              redeem handoff → seed GMS session → /admin
                    ├─ /api/v1/*  /socket.io → GMS backend (:7200)
                    └─ /*                   → GMS frontend (:7201)

IdP admin console (:7300/admin, gated to IDP_ADMIN_GROUP)
                    ├─ manage local users, group membership, per-app roles/offices
                    ├─ read-only OIDC client registry (/admin/clients — see below)
                    ├─ JWKS rotate/retire (live — no restart needed)
                    ├─ kill-session, disable user, force-logout sweep
                    └─ tamper-evident audit log (hash-chained, /admin/audit + /admin/audit/verify)

   store: PostgreSQL `idp` (oidc artifacts incl. SSO session, signing keys,
          users/groups, clients, RP + GMS role mappings, app entitlements, admin audit log)
```

The current SSO browser UI source lives entirely under `SSO/frontend/src/views`.
`SSO/backend` never renders HTML — every route still calls `res.render(view, locals)`,
but that always returns a JSON `{ view, locals }` view model (see
`src/http/view-model.ts`); only `SSO/frontend` turns it into a page. The backend has
no `ejs` dependency and no build-time dependency on the frontend's view source.

Ports & databases (each app fully isolated — no shared DB):

| App              | Backend                   | Frontend                       | Database  |
| ---------------- | ------------------------- | ------------------------------ | --------- |
| DMS/EDAMS        | 7100                      | 7101                           | `DMS`     |
| GMS (Guest Mgmt) | 7200                      | 7201 (staff via gateway :4200) | `gmsdev`  |
| **IdP**          | **7300** (+ gateway 4200) | **7301** (browser proxy)       | **`idp`** |

## Run (dev)

```bash
cd SSO/backend
npm install
cp .env.example .env          # then fill secrets (see below)
npm run db:migrate            # apply schema to the `idp` database
npm run db:seed:dev           # local test user admin@examplecorp.com / demo
npm run dev                   # http://localhost:7300 (API/OIDC runtime)

cd ../frontend
npm install
npm run dev                   # http://localhost:7301 (browser entry — use this in the browser)
```

Prereqs: PostgreSQL with an `idp` database (`CREATE DATABASE idp;`). No Redis required
(the Postgres adapter persists sessions); Redis is a Phase-9 scale-out option.

## Container deployment

The container listens on port **7300** by default (the same port as the issuer) and
serves JSON view models only — it never renders HTML, so it has no dependency on
`SSO/frontend`'s template source. Build it from the `SSO/` root (`docker build -f
backend/Dockerfile`) purely for Docker-context convenience with the rest of the
platform, not because the backend image needs anything from `frontend/`.
Configure a production `IDP_ISSUER`, database URL, cookie keys, audit and TOTP keys,
client secrets, and any GMS bridge settings through the deployment environment. Apply
`npm run db:migrate` as a separate deployment step before starting a production
replica; startup deliberately does not run migrations in production.

```bash
cd SSO
docker build -f backend/Dockerfile -t examplecorp-idp .
docker run --rm -p 7300:7300 --env-file backend/.env examplecorp-idp
```

Key env (`.env`):

- `DATABASE_URL` — IdP's own DB (default `postgres://postgres:change-me@localhost:5432/idp`).
- `LDAP_URL` — set to enable AD; leave empty to use the local user store only.
- `DMS_API_BASE_URL` / `DMS_INTERNAL_API_KEY` — authenticated internal DMS admin API.
- `GMS_API_BASE` / `GMS_INTERNAL_API_KEY` — authenticated internal GMS bridge/admin API.

## Verification harnesses (`test-scripts/`)

The fast, dependency-free security-primitives suite runs in CI and locally with:

```bash
npm test
```

With the IdP running (and the target app for the last two):

```bash
node test-scripts/e2e-oidc.mjs        # full auth-code+PKCE: login→consent→token, checks id_token claims
npx tsx test-scripts/bridge-test.ts   # mint GMS session, verify HS256 token + gmsdev rows
npx tsx test-scripts/gms-live-test.ts # call a protected GMS API with the bridged token (GMS must run)
node test-scripts/dms-sso-test.mjs    # full DMS SSO: DMS authorize→IdP→code→DMS callback (DMS+Redis must run)
node test-scripts/security-self-service-test.mjs
                                       # /admin/clients (read-only + no secret leak), portal
                                       # self-service password change (validation + a real
                                       # round-trip that restores admin@examplecorp.com's
                                       # password to "demo" before exiting), and session kill
```

## OIDC client registry (`/admin/clients`)

The admin console's **Clients** page lists every registered relying party (EDAMS, GMS,
MRS, the portal itself) — name, `client_id`, active flag, grant types, redirect URIs,
and post-logout redirect URIs. It never renders `client_secret`.

**This page is read-only, on purpose.** `oidc-provider` v8 loads the `clients` array once at
boot (`oidc/provider.ts` → `oidc/clients.ts#loadClients`) and its `Client.find()` caches every
statically-configured client for the life of the process
(`node_modules/oidc-provider/lib/models/client.js`) — there is no supported way to add, update,
or deactivate a client on a running instance the way `jwks.ts#reloadProviderKeys` does for
signing keys (that helper works because oidc-provider's own keystore initializer is designed to
be re-run safely; the client-side equivalent, `clientAddStatic`, throws on a duplicate
`client_id` and has no matching "remove"/"replace"). A write here could therefore update
`idp_clients` in Postgres without ever taking effect on the running IdP until a restart — a
control that _looks_ live but silently doesn't work would be worse than no control at all. So:
to onboard or change a client, edit `clientSeed` in `config.ts` (or `idp_clients` directly) and
restart the IdP; use `/admin/clients` to verify what's currently registered and running.

## Onboarding a new app

- **OIDC app:** insert a row in `idp_clients` (or add to `clientSeed` in `config.ts`) with its
  redirect URIs. That's it.
- **Non-OIDC app (like GMS):** add a bridge adapter modeled on `src/bridge/gms.ts` + a launcher
  entry in `src/portal/router.ts`.

## Layout

```
src/
  config.ts            env-driven config (issuer, clients, ttls, ldap, gms bridge, admin secrets)
  main.ts              express app: mounts oidc-provider + our routes; purge job; graceful shutdown
  oidc/provider.ts     oidc-provider configuration
  oidc/clients.ts      client registry (seed + load from idp_clients)
  adapters/postgres.ts oidc-provider Adapter (single-table, incl. SSO Session)
  jwks.ts              persisted RS256 signing keys — rotate/retire take effect live, no restart
  auth/                ldap.service, local-users (+ MFA lockout), password (scrypt), account
                        (findAccount), totp.ts (encrypted at rest), revoke.ts, logout-notify.ts
  interactions/        login router + CSRF + auto-consent for first-party clients
  bridge/              GMS token bridge (gms.ts) + OIDC-RP router + one-time handoff store
                        (origin/session-bound, short-TTL)
  gateway/             server.ts (same-origin GMS proxy :4200). The legacy /gms/api relay
                        (gateway/router.ts) was dead code (401'd on a cookie nothing ever set) and
                        has been removed.
  admin/               admin console: users, groups/entitlements, JWKS, kill-session, audit log,
                        read-only OIDC client registry (router.ts, audit.ts, csrf.ts)
  portal/              authenticated OIDC-RP launcher (router.ts) + portal session store;
                        also serves self-service security (MFA, own password, own sessions,
                        own sign-in history) at /portal/security
  db/                  pool, migrate runner, dev seed, verify-audit-chain.ts
migrations/            001_init.sql … 007_phase_e.sql (numbered, sequential — see db/migrate.ts)
../frontend/src/views/ EJS source (login, consent, error, portal, admin/*, security,
                        totp, change-password) — copied to dist/views at build time
```

## Related docs (repo root)

- `SSO-ARCHITECTURE.md` — design, identity planes, gateway vs shell, honest status
- `SSO-INTEGRATION-GUIDE.md` — **how to fit future apps** (new + legacy PHP/JS), 3 modes
- `SSO-OPERATIONS.md` — setup, run, deploy, troubleshooting
- `SSO-SESSION-LOG.md` — full build record

