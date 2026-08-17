# Example Corp SSO — Setup, Run & Deploy

Operational runbook for the IdP and its integrations. Architecture:
`SSO-ARCHITECTURE.md`. Onboarding: `SSO-INTEGRATION-GUIDE.md`.

---

## 1. Service matrix

| Service | Dir | Backend | Frontend | Database | Notes |
|---------|-----|---------|----------|----------|-------|
| IdP | `IdP/identity` | 4100 | 4100 (own EJS UI) | `idp` | OIDC provider + portal + gateway |
| GMS gateway | `IdP/identity` (same process) | 4200 | — | — | same-origin reverse proxy for GMS staff SPA |
| DMS/EDAMS | `DMS 10` | 4000 | 3000 | `DMS` | OIDC client (Pattern A) |
| GMS | `GMS RELEASE V3` | 5000 | 5001 | `gmsdev` | token bridge (Pattern B) |

All on one local PostgreSQL 17 (`localhost:5432`, `postgres` / `leadfreak`) but
**separate databases** — no app shares a DB. IdP needs no Redis in dev (Postgres
persists sessions); DMS uses Redis for its OIDC nonce + revocation.

**Human entry point:** the SSO portal — open **`http://localhost:4100/`** (redirects to
`/portal`) and sign in `admin@examplecorp.com` / `demo`. From the portal, "Open EDAMS" or
"Open GMS" launch each app with no second login.

**GMS gateway (why :4200 + a funny hostname):** the GMS staff SPA is served through a
same-origin reverse proxy at **`http://gms.localtest.me:4200`** (that hostname resolves to
127.0.0.1 with no hosts-file edit). This is required because GMS's dev frontend force-routes
its API to `:5000` for literal `localhost` hosts — a non-loopback host lets it honor a
same-origin API base, so the bridged session works with no CORS and **no GMS code change**.
The GMS frontend must be started with `NEXT_PUBLIC_API_BASE_URL=http://gms.localtest.me:4200/api/v1`.
Staff never type a GMS password; they arrive already signed in on `/admin` (or `/reception`,
`/host` per role). GMS's own guest registration and staff-login pages remain untouched and
directly reachable on :5001.

---

## 2. First-time setup

```bash
# 1) IdP database (once)
psql -h localhost -U postgres -c "CREATE DATABASE idp;"
psql -h localhost -U postgres -d idp -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"

# 2) IdP
cd "IdP/identity"
npm install
cp .env.example .env            # fill secrets (see §4)
npm run db:migrate              # 001_init, 002_gms_bridge
npm run db:seed:dev             # local user admin@examplecorp.com / demo (+ group + mappings)

# 3) DMS — apply the SSO migration + env
cd "../../DMS 10/backend"
npm run db:migrate              # includes 20260705000001-user-external-sub
# .env already carries the AUTH_*/OIDC_* block (see repo)

# GMS needs no setup — it is bridged, not modified.
```

---

## 3. Run (dev) — start order

```bash
# a) IdP (also starts the GMS gateway on :4200)
cd "IdP/identity" && npm run dev            # http://localhost:4100  (+ gateway :4200)

# b) DMS backend + frontend  (needs Redis on 6379)
cd "DMS 10/backend"  && npm run dev         # :4000
cd "DMS 10/frontend" && npm run dev         # :3000

# c) GMS backend + frontend (needed for the GMS tile to work)
cd "GMS RELEASE V3/backend"  && npm run dev # :5000
cd "GMS RELEASE V3/frontend" && npm run dev # :5001 (served to staff via the gateway :4200)
```

The GMS frontend has a **`.env.local`** (local override, not tracked auth code) that points its
API + socket at the gateway origin:
```
NEXT_PUBLIC_API_BASE_URL=http://gms.localtest.me:4200/api/v1
NEXT_PUBLIC_SOCKET_URL=http://gms.localtest.me:4200
```
This is what makes the staff SPA's own API calls go same-origin (no CORS) when served via the
gateway. Direct `http://localhost:5001` access is unaffected — the GMS frontend force-routes
loopback hosts straight to `:5000` regardless of this value. The gateway proxies `/api/v1` and
`/socket.io` to the GMS backend and everything else to the GMS frontend.

Try it:
- IdP discovery: `curl http://localhost:4100/.well-known/openid-configuration`
- SSO portal: open `http://localhost:4100/portal`
- DMS SSO: open `http://localhost:3000/login` → "Sign in with Example Corp SSO".
- Dev login: `admin@examplecorp.com` / `demo`.

Automated verification harnesses (in `IdP/identity/test-scripts/`):
```bash
node test-scripts/e2e-oidc.mjs        # OIDC end-to-end + id_token claims
npx tsx test-scripts/bridge-test.ts   # mint GMS token + verify gmsdev rows
npx tsx test-scripts/gms-live-test.ts # call a protected GMS API with the bridged token
node test-scripts/dms-sso-test.mjs    # full DMS SSO round-trip
```

---

## 4. Configuration reference (IdP `.env`)

| Var | Meaning |
|-----|---------|
| `IDP_ISSUER` | Canonical URL (`iss`). Dev `http://localhost:4100`, prod `https://idp.examplecorp.com` |
| `DATABASE_URL` | IdP's own DB (`idp`) |
| `COOKIE_KEYS` | SSO session cookie signing keys (comma-separated; rotate by prepending) |
| `LDAP_URL` etc. | Enable AD auth; empty → local user store only |
| `EDAMS_/GMS_/MRS_CLIENT_SECRET` | seeded client secrets |
| `GMS_JWT_SECRET` / `GMS_JWT_REFRESH_SECRET` | **must equal GMS's runtime secret** (GMS loads `.env` then `.env.development` with override) |
| `GMS_DATABASE_URL` | GMS DB so the bridge can provision users |

`dotenv` is loaded with `override:true` so a machine-wide `DATABASE_URL` (e.g. a
Railway var) can't shadow the IdP's local DB.

---

## 5. Production deployment

**Topology — subdomains behind your existing reverse proxy / load balancer:**
```
idp.examplecorp.com  → IdP (4100)
dms.examplecorp.com  → DMS frontend/back
gms.examplecorp.com  → GMS frontend/back
```
The load balancer does **host-based routing + TLS termination**; the IdP does
identity. Keep them separate (see architecture §3 — no mandatory front-door shell).

Per service:
- **IdP:** `npm run build` (compiles + copies `views/`), `npm start`. Run
  `npm run db:migrate` as a deploy step. Set `NODE_ENV=production`, real
  `IDP_ISSUER` (https), strong `COOKIE_KEYS`, real client secrets, and
  `LDAP_*` for AD. Put behind TLS (the app trusts `x-forwarded-*`, `proxy=true`).
- **DMS:** set the `AUTH_*`/`OIDC_*` block to the prod issuer; flip
  `LOCAL_JWT_MOCK=false` at cutover (SSO becomes the only login).
- **GMS:** unchanged. Set the IdP's `GMS_JWT_SECRET` to GMS's **production**
  `JWT_SECRET` and `GMS_DATABASE_URL` to the prod GMS DB.

**Cookies / same-origin for the GMS SPA:** either serve GMS behind the IdP gateway
relay (same origin) or host both under a shared parent domain so the bridged
session applies cleanly. Cross-origin dev works at the API level; the SPA handoff
wants same-origin.

**Secrets & keys (hardening / Phase 9):**
- Move JWKS signing keys and client secrets to a secrets manager / KMS; rotate
  JWKS on a schedule (overlap window ≥ max token TTL).
- Add Redis for multi-instance session sharing before scaling the IdP horizontally.
- Enable MFA/lockout for AD accounts (local-store lockout already implemented).

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| IdP connects to the wrong DB | A global `DATABASE_URL` in your shell — the IdP `.env` overrides it, but check `echo $DATABASE_URL` if a test script bypasses config |
| GMS returns 401 to a bridged token | `GMS_JWT_SECRET` ≠ GMS's runtime secret (remember `.env.development` override) |
| DMS callback 500 on first SSO login | Redis down (nonce is fail-closed), or the user has no group mapping in `idp_role_mappings` |
| `/auth/callback` bounces to `/login` | Ensure `/auth/callback` is in `AuthGuard` PUBLIC_PATHS (already added) |
| Guest can't reach GMS | Guests must use GMS's **native** login — do not route them through SSO/the bridge |
