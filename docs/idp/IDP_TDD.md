# IDP_TDD — Technical Design Document

**System:** Standalone Identity Provider (IdP) for EDAMS
**As of:** 2026-07-02

---

## 1. Architecture Overview

```
                +-------------------+        JWKS / discovery
   Browser  --> |   IdP service     | <--------------------------+
                |  (Express +       |                            |
                |   oidc-provider)  |     OIDC (code + PKCE)     |
                +----+----------+---+ <----------------------+   |
                     |          |                            |   |
              +------+--+   +---+-----+                  +---+---+---+
              | IdP DB  |   | Redis   |                  |  EDAMS    |
              |(Postgres|   |(sessions|                  |  backend  |  (Relying Party)
              | edams_  |   | nonce,  |                  |  = OIDC   |
              | idp)    |   | revoke) |                  |  client   |
              +---------+   +---------+                  +-----------+
                                                          (future RPs too)
```

The IdP is a new, independently deployed Node/TS service. It uses the **`oidc-provider`** library (Panva) for spec-compliant OAuth2/OIDC, with EDAMS's ported identity logic supplying accounts, claims, and interactions.

## 2. Stack (deliberately mirrors EDAMS)

| Layer | Technology |
|---|---|
| Runtime | Node.js 22 / TypeScript |
| HTTP | Express 5 |
| OIDC/OAuth2 | `oidc-provider` (Panva) |
| ORM / DB | Sequelize 6 + PostgreSQL (`edams_idp`) |
| Cache/session | Redis (sessions, nonce/state, revocation) |
| Migrations | Umzug (globs `migrations/*.sql`) |
| Keys | RSA 2048; JWKS with `kid` rotation |

## 3. Repository Layout (`idp/`, sibling of `backend/`, `frontend/`)

```
idp/
  src/
    server.ts                 # Express bootstrap, mounts oidc-provider
    config/env.ts             # zod-validated env (modeled on backend/src/config/env.ts)
    oidc/provider.ts          # configure oidc-provider
    oidc/adapter.ts           # Sequelize persistence adapter for provider models
    oidc/claims.ts            # findAccount + claims (tenant_id, roles, groups)
    oidc/interactions.ts      # login / mfa / select-tenant / consent
    identity/                 # ported user/tenant/role/MFA services
    infrastructure/db/models  # ported Sequelize models
    infrastructure/redis.ts
    keys/                     # RSA/JWKS load + rotation
    audit/                    # hash-chained audit (ported)
    admin/                    # admin API (users/tenants/clients)
  migrations/*.sql            # Umzug
  scripts/migrate.ts, seed-core.ts, generate-rsa-keys.js
  views/                      # login / mfa / select-tenant / consent UI
  Dockerfile
  .env.example
```

## 4. Data Model

**Ported from** `backend/src/infrastructure/database/models/index.ts`:
- `User` (id, email, `passwordHash`, firstName, lastName, isActive, `isMfaEnabled`, `mfaSecret`, `mfaTempSecret`, `mustChangePassword`, `failedLoginCount`, `lockedUntil`, `externalSub`, timestamps).
- `Tenant` (slug id, name, isActive, quotas — quotas optional in IdP).
- `UserTenant` (userId, tenantId; unique per pair).
- `Role`, `UserRole` (coarse roles/groups asserted to clients).
- `AuthSession` (session/refresh tracking) — optional; `oidc-provider` also persists sessions.

**New:**
- `OidcClient` (client_id, secret hash, redirect URIs, grant types, response types, scopes, tenant binding, trusted-first-party flag).
- Persisted `oidc-provider` models via the Sequelize adapter: Grant, Session, AuthorizationCode, AccessToken, RefreshToken, Interaction, DeviceCode, etc.

**Note:** fine-grained EDAMS permissions (`RolePermission`, the 40 permissions) **stay in EDAMS**. The IdP only asserts roles/groups.

## 5. Token & Claims Contract

Access token = JWT, verifiable via JWKS. Claim set aligned to what EDAMS already consumes so `resolveACL()` / permission mapping keep working:

```jsonc
{
  "sub": "<user uuid>",
  "email": "user@example.com",
  "email_verified": true,
  "name": "First Last",
  "tenant_id": "examplecorp",        // set after tenant selection
  "roles": ["RECORDS_OFFICER"],     // coarse roles
  "groups": ["..."],                // optional group assertions
  "iss": "https://idp.<domain>/",
  "aud": "edams-api",
  "iat": 0, "exp": 0, "jti": "<uuid>"
}
```

EDAMS's `POST /auth/callback` maps `roles`/`groups` → its 40 permissions via the existing `idp_role_mappings` table and JIT-provisions a local user projection by email (`externalSub` link).

## 6. Key Management

- RSA 2048 keypair; JWKS exposed at `/jwks.json` with `kid`.
- Dev keys via env (reuse `scripts/generate-rsa-keys.js`).
- Prod keys injected via mounted secret / KMS — never committed.
- Rotation: publish new key in JWKS, sign with new `kid`, retire old key after propagation TTL; consumers auto-refresh JWKS (EDAMS caches with ~1h TTL and rotates on unknown `kid`).

## 7. Interactions (custom UI)

`oidc-provider` delegates to interaction endpoints. Ported from `backend/src/modules/auth/auth.routes.ts`:
1. **Login** — email+password verify, `failedLoginCount`/`lockedUntil` lockout, `mustChangePassword`.
2. **MFA/TOTP** — setup/confirm/validate/disable.
3. **Select-tenant** — `user_tenants` lookup; multi-tenant prompt, single-tenant auto; selected tenant bound to the grant so the token is tenant-scoped.
4. **Consent** — auto for trusted first-party clients (EDAMS); consent screen scaffolded for third-party.

## 8. Security Design

- **PKCE** required on the authorization-code flow.
- **State/nonce replay protection** — reuse the Redis single-use nonce pattern from `auth.routes.ts`.
- **Refresh-token rotation** + reuse detection.
- **Revocation** — `revoked:{jti}` in Redis with TTL = remaining token lifetime; enforced via introspection/verification.
- **MFA + lockout** as above.
- **Audit** — hash-chained `AuditLog` with events `AUTH_LOGIN`, `AUTHN_FAILURE`, MFA/enrolment events, admin mutations.

## 9. Two-Phase Tenant Selection in OIDC Terms

Tenant is selected **during the IdP interaction**, so the issued token is already tenant-scoped (matching current EDAMS UX). `switch-tenant` = a fresh authorization request (silent or `prompt=login`) for the new tenant. This keeps EDAMS's tokens single-tenant and avoids multi-tenant token ambiguity. (Alternative — issue a multi-tenant identity token and let EDAMS re-scope — documented but not recommended.)

## 10. Integration with EDAMS (Relying Party)

- **Config** (`backend/src/config/env.ts` + `.env`): `AUTH_ISSUER=https://idp.<domain>/`, `AUTH_JWKS_URI=<issuer>/jwks.json`, `AUTH_AUDIENCE`, `OIDC_CLIENT_ID/SECRET`, `OIDC_REDIRECT_URI`, `OIDC_SCOPES`; `LOCAL_JWT_MOCK=false`.
- **Callback** (`POST /auth/callback`): map `roles`/`groups` → permissions via `idp_role_mappings`; JIT-provision local user by email. `resolveACL()` / `requirePermission()` unchanged.
- **Frontend**: replace dev email-only login (`frontend/app/(auth)/login/page.tsx`) with a redirect to EDAMS's existing `GET /auth/oidc/authorize`. `apiClient.ts` silent-refresh and `AuthGuard` largely unchanged; `select-tenant`/`TenantSwitcher` adjusted per §9.

## 11. Deployment Topology

- IdP container on a distinct port (dev **4100**), own Postgres DB `edams_idp`, Redis (shared or dedicated).
- Prod: subdomain `idp.<domain>` with TLS termination; secrets via env/secret store; JWKS rotation schedule; health/readiness endpoints; DB backups.
- Migrations (`npm run db:migrate`) run on deploy; `seed-core.ts` seeds default tenants, roles, an admin user, and the EDAMS OIDC client.

---

*Related: [IDP_BRD.md](IDP_BRD.md), [IDP_FRD.md](IDP_FRD.md), [IDP_IMPLEMENTATION_PLAN.md](IDP_IMPLEMENTATION_PLAN.md)*
