# Example Corp Identity Provider — backend

The OIDC provider, admin console API, SSO portal API and GMS gateway for the
Example Corp platform. Express 5 + [`oidc-provider`](https://github.com/panva/node-oidc-provider)
(Panva) on PostgreSQL, port **7300**.

This process **never renders HTML for the app's own pages**. Every route calls
`res.render(view, locals)`, but `http/view-model.ts` wraps that so it returns a
JSON `{ view, locals }` view model instead; `SSO/frontend` (Next.js, port 7301)
is the only process that turns one into a page. The exceptions — three
`oidc-provider`-owned HTML responses — are listed in `src/http/csp.ts`.

For how this system fits the platform, see `../CLAUDE.md`. For a production
deploy, `/DEPLOYMENT-GUIDE.md` at the repo root is canonical.

## What it does

- **One login, every app.** A persistent SSO session cookie means signing in
  once covers DMS, GMS, and any future relying party.
- **DMS/EDAMS** integrates as a standard OIDC relying party (RS256 + JWKS).
- **GMS** is signed in through a **token bridge**: SSO performs the OIDC
  handoff, then asks GMS's authenticated internal API to mint the GMS session
  and provision the user if needed. GMS itself is unchanged.
- **Identity source:** Active Directory over LDAP (`ldapts`) as primary, with a
  local PostgreSQL user store as fallback for non-AD and service accounts.
- **Self-service security** (`/portal/security`): users enroll MFA, review and
  individually revoke their own live sessions, read their own sign-in history,
  and — for local-source accounts — change their own password, without an admin.
- **Admin console API** (`/admin`, gated to `IDP_ADMIN_GROUP`): local users,
  group membership, per-app roles and offices, live JWKS rotate/retire,
  kill-session, force-logout sweep, and a hash-chained tamper-evident audit log.

## Registered clients

`config.ts` → `clientSeed` is the one place an OIDC client is registered. There
are three, and each is scope-restricted so no relying party sees another's role
claims (migration `012_client_scopes.sql`):

| `client_id` | Who | Scopes |
|---|---|---|
| `edams` | DMS (see `../CLAUDE.md` on why the id is not `dms`) | `openid profile email ad_groups edams_roles` |
| `gms` | the GMS token bridge | `openid profile email ad_groups gms_roles` |
| `portal` | this system's own launcher | `openid profile email ad_groups` |

The **portal launcher's tiles** are a separate list — `src/portal/catalog.ts` →
`APP_REGISTRY` (`catalog()` derives the tiles from it; the admin console's "App
access" list derives from it too). Registering a client does not create a tile,
and vice versa; a new system needs both entries.

Editing a client's `*_REDIRECT_URIS` / `*_LOGOUT_URIS` in an env file only reaches
a client whose stored secret is still a dev default. For an existing client run
`npm run client:uris` (dry run) and `npm run client:uris -- --apply`, then restart.
Public clients are not supported; every client uses `client_secret_post`.

## Routes

```
/                       → redirect to /portal
/.well-known/*          discovery + jwks (oidc-provider)
/authorize, /authorize/:uid, /token, /me, /jwks, /session/*
/interaction/:uid       login, MFA, password change (rate-limited)
/portal                 authenticated launcher + /portal/security self-service
/admin                  admin console API (IDP_ADMIN_GROUP only)
/bridge/gms/*           GMS token bridge (OIDC RP → mint HS256 GMS session)
/api/v1/*               versioned JSON API (auth, admin, admin-mutations, portal, platform)
/api/v1/internal/gms    GMS role grants (internal, API-key auth); also at /internal/gms
/health                 liveness (issuer + whether the GMS bridge is on)
/health/ready           readiness — real DB round-trip, 503 if Postgres is down
/metrics                operational counters, authenticated (see ops/metrics.ts); JSON, or Prometheus text with ?format=prometheus (ops/prometheus.ts)
/api-docs, /api-docs.json   Swagger UI. On outside production; in production only
                            when ENABLE_API_DOCS=true
```

**Gateway.** `src/gateway/server.ts` is a *second* Express app started inside
this same process (default port **4200**) when the GMS bridge is enabled. It
reverse-proxies GMS's frontend and API under one origin so the SameSite cookies
set during the handoff survive. It is not a separate deploy unit.

**Background work.** Two in-process `setInterval` jobs, no worker process:
an hourly purge of expired OIDC artifacts, login events older than 90 days and
stale web sessions; and a 30-minute AD group re-sync for users with a live
session (a no-op when LDAP is not configured).

## Run (development)

```bash
cd SSO/backend
npm install
cp .env.example .env      # then fill in secrets
npm run db:migrate        # apply schema to the `idp` database
npm run db:seed:dev       # local test user admin@examplecorp.com / demo
npm run dev               # http://localhost:7300 — OIDC/API runtime

cd ../frontend
npm install
npm run dev               # http://localhost:7301 — open THIS in the browser
```

Prerequisites: Node 22 and PostgreSQL with an `idp` database
(`CREATE DATABASE idp;`). Redis is **optional** — set `REDIS_URL` only to share
rate-limit counters across processes; without it every limiter falls back to a
per-process in-memory store (`src/infrastructure/redis.ts` explains the
trade-off).

`npm run dev` runs migrations automatically. Production deliberately does not —
run `npm run db:migrate:prod` as a separate deploy step.

## Configuration

**Production reads `.env.production` and nothing else.** `.env` is the
development file and is never read when `NODE_ENV=production`; a missing
`.env.production` is a hard refusal to start, not a silent fallback. The reason
is spelled out at the top of `src/config.ts` and matters more here than in the
other two systems: every `env()` call in this file has a fallback, so SSO does
not fail loudly on bad configuration — it boots happily on the `idp` dev
database with a localhost issuer baked into every token it signs.

```bash
npm run env:verify:prod   # print the resolved production config — database,
                          # issuer, AD settings, registered clients — without
                          # starting the service or binding a port
```

Key variables (`.env.example` has the full surface):

- `DATABASE_URL` — SSO's own database. A machine-wide `DATABASE_URL` left over
  from Railway/Render has bitten this platform repeatedly; config.ts refuses to
  boot on an ambient one the loaded env file did not itself define.
- `IDP_ISSUER` — must match the URL browsers actually reach. It is baked into
  every token.
- `COOKIE_KEYS`, `EDAMS_CLIENT_SECRET`, `GMS_CLIENT_SECRET`,
  `PORTAL_CLIENT_SECRET` — boot refuses on the dev defaults in production.
- `LDAP_*` — set `LDAP_URL` to enable AD; leave empty for the local store only.
- `DMS_API_BASE_URL` / `DMS_INTERNAL_API_KEY`, `GMS_API_BASE` /
  `GMS_INTERNAL_API_KEY` — the authenticated internal admin APIs SSO calls.

## Production

```bash
npm run build
npm run db:migrate:prod
npm run start:prod        # forces NODE_ENV=production, then node dist/main.js
```

`npm run start:prod` goes through `scripts/run-with-env.cjs` because neither
PowerShell nor cmd.exe has a portable inline `VAR=value command` syntax, and
`NODE_ENV` has to be set *before* the process starts for the env-file contract
to pick the right file.

A container image is also supported (`Dockerfile`, built from the `SSO/` root
for Docker-context convenience). It is optional — nothing about this backend
requires Docker.

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | nodemon + tsx on `src/main.ts` |
| `npm run build` / `npm start` | `tsc` to `dist/`, then `node dist/main.js` |
| `npm run start:prod` | as above, with `NODE_ENV=production` forced |
| `npm run typecheck` | `tsc --noEmit` |
| `npm test` | Jest — writes `test-results.json` |
| `npm run test:status` | regenerate `docs/TEST_STATUS.md` from that file |
| `npm run db:migrate` / `:prod` | apply `migrations/*.sql` in order |
| `npm run db:seed:dev` / `:prod` | dev login `admin@examplecorp.com` / `demo` |
| `npm run db:seed:users` | seed the local user store |
| `npm run db:backup` / `:prod` | `pg_dump` via `scripts/db-backup.ts` |
| `npm run data:export-directory` | write the company directory (names and addresses, no secrets) for DMS's department-data compiler to match names against (`DMS/Collected-Data/.sso-directory.json`, git-ignored) |
| `npm run data:quality` | **read-only** report of accounts whose address or name looks wrong: mistyped company domain, no dot in the domain, throw-away address, empty name, possible duplicate person, each with a suggested correction. Optional `-- --csv=file.csv`. Never changes an account |
| `npm run audit:verify` | verify the admin audit log's hash chain (lists every break and whether it is acknowledged) |
| `npm run db:ack:dev-audit` | **dev only**: acknowledge the ten July 2026 breaks in the dev database (refuses on production and the mirror) |
| `npm run env:verify:prod` | resolve and print production config, start nothing |

## Verification harnesses (`test-scripts/`)

`npm test` is the fast, dependency-free suite that runs in CI. The scripts below
drive real running services and are run by hand:

```bash
node test-scripts/e2e-oidc.mjs          # auth-code + PKCE end to end, checks id_token claims
npx tsx test-scripts/bridge-test.ts     # mint a GMS session, verify the HS256 token + gmsdev rows
npx tsx test-scripts/gms-live-test.ts   # call a protected GMS API with that token (GMS must run)
node test-scripts/dms-sso-test.mjs      # DMS authorize → SSO → code → DMS callback (DMS + Redis must run)
node test-scripts/browser-clickthrough.mjs      # headless Chromium walk-through; writes screenshots/
```

The console and the sign-in pages are covered by the Playwright suite in `SSO/frontend/e2e/` (`npm run e2e` there), which replaced the
server-rendered-console scripts removed on 2026-10-11.

## How the Applications page (`/admin/clients`) changes a client without a restart

The page lists the registered relying parties (name, `client_id`, state, scopes, addresses, usage, secret age) and lets the
**platform administrator** edit the addresses, switch a client off and on, restore the configured addresses and rotate the secret
(shown once). It never renders `client_secret` otherwise. The portal client is protected: the console itself signs in through it, so
it cannot be edited, switched off or re-keyed here (Restore is its recovery path).

It used to be read-only, for a good reason: `oidc-provider` freezes a `clients: [...]` list given at boot for the life of the process.
The fix is that the provider is no longer given a list. A client it does not know statically is read through the adapter's `Client`
model (`adapters/postgres.ts` -> `oidc/clients.ts#findClientMetadata`) on every request, and the provider rebuilds the client whenever
its stored metadata changes. So an edit to `idp_clients` applies to the **next request**. `test-scripts/verify-client-live.ts` proves it
against the running dev SSO (an unregistered address is refused, registered through the same function the console calls and accepted at
once, restored and refused again, a client switched off is refused, switched on and accepted).

Which clients exist is still decided by the code (`config.ts#clientSeed`, `portal/catalog.ts`, the role code): adding a system is a
deployment, not a form. The console manages what an operator changes in place.

## Layout

```
src/
  config.ts            env contract + issuer, clients, TTLs, LDAP, GMS bridge, admin secrets
  main.ts              express app, route mounts, purge/AD-resync jobs, graceful shutdown
  oidc/                provider.ts (oidc-provider config), clients.ts (seed + load)
  adapters/postgres.ts oidc-provider Adapter — single table, includes the SSO Session
  jwks.ts              persisted RS256 signing keys; rotate/retire take effect live
  auth/                ldap.service, local-users (+ MFA lockout), password (scrypt),
                       account (findAccount), totp (encrypted at rest), revoke,
                       logout-notify, client role claims, AD re-sync worker
  interactions/        login router, CSRF, auto-consent for first-party clients
  bridge/              GMS token bridge (gms.ts) + OIDC-RP router + one-time,
                       origin-bound, short-TTL handoff store
  gateway/server.ts    the same-origin GMS proxy on :4200
  admin/               console API: users, groups, entitlements, JWKS, audit log,
                       client registry (live edits), DMS/GMS internal API clients
  portal/              launcher (router.ts), tiles (catalog.ts), portal session store
  api/v1/              versioned JSON API + the OpenAPI document
  http/                view-model.ts (the render → JSON wrapper), csp.ts
  db/                  pool, migrate runner, seeds, verify-audit-chain
  infrastructure/      redis (optional), rate-limit store, internal API client
  ops/metrics.ts       operational counters + who may read them
migrations/            001_init.sql … 013_audit_chain_v2.sql, applied in order by db/migrate.ts
test-scripts/          live verification harnesses (see above)
```

## Related documentation

- `../docs/sso/SSO-ARCHITECTURE.md` — design, identity planes, gateway vs shell
- `../docs/sso/SSO-INTEGRATION-GUIDE.md` — onboarding a new relying party
- `../docs/sso/SSO-INTEGRATION-CODE-REFERENCE.md` — exact env values + working code
- `../docs/sso/SSO-OPERATIONS.md` — key rotation, sessions, audit chain
- `../docs/platform/PLATFORM_ARCHITECTURE.md`, `../docs/platform/ADR.md`
- `/DEPLOYMENT-GUIDE.md`, `/SERVER-DEPLOYMENT-TODO.md` at the repo root
