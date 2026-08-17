# IDP_IMPLEMENTATION_PLAN — Step-by-Step Develop & Deploy

**System:** Standalone Identity Provider (IdP) for EDAMS
**As of:** 2026-07-02

> Phased plan. Each phase ends with a verification gate. Nothing is marked "done" until the gate is actually run and recorded in `CURRENT-STATUS.md`.

---

## Phase 0 — Documentation & sign-off
1. Place BRD/FRD/TDD/this plan in `docs/idp/`.
2. Review responsibility boundary (IdP = authN + identity; EDAMS = authZ) with stakeholders.
3. **Gate:** docs approved; claim contract ([IDP_TDD.md](IDP_TDD.md) §5) agreed with EDAMS team.

## Phase 1 — Scaffold `idp/` service
1. Create `idp/` (sibling of `backend/`, `frontend/`); copy `tsconfig`, ESLint/Prettier, scripts pattern from `backend/`.
2. Add `src/config/env.ts` (zod-validated) modeled on `backend/src/config/env.ts`.
3. Add Express bootstrap `src/server.ts`, Redis client, health endpoints.
4. **Gate:** `npm run dev` boots; `/healthz` responds.

## Phase 2 — Data layer & migrations
1. Port models: `User`, `Tenant`, `UserTenant`, `Role`, `UserRole`, `AuthSession`; add `OidcClient`.
2. Write Umzug SQL migrations for the IdP schema; wire `scripts/migrate.ts`.
3. `scripts/seed-core.ts` — seed tenants, roles, admin user, EDAMS client; `generate-rsa-keys.js` for dev keys.
4. **Gate:** `npm run db:migrate && npm run db:seed` succeed against a local `edams_idp`.

## Phase 3 — OIDC provider
1. Configure `oidc-provider` in `src/oidc/provider.ts`: PKCE required, refresh rotation, introspection, revocation, RP-initiated logout, discovery.
2. Implement Sequelize `adapter` (`src/oidc/adapter.ts`) for provider models.
3. `findAccount` + `claims()` (`src/oidc/claims.ts`) producing the claim set in [IDP_TDD.md](IDP_TDD.md) §5.
4. Load JWKS from `keys/`; expose `/jwks.json` and discovery.
5. **Gate:** discovery + JWKS return valid docs; a test client can reach `/authorize`.

## Phase 4 — Interactions (login, MFA, tenant, consent)
1. Port login (password verify, lockout, forced change).
2. Port MFA/TOTP setup/confirm/validate/disable.
3. Implement select-tenant interaction (multi vs single); bind tenant to grant.
4. Consent (auto for trusted first-party).
5. Port nonce/state replay protection, revocation set, hash-chained audit.
6. **Gate (manual OIDC conformance):** full code+PKCE flow → login → MFA → select-tenant → consent → code → `POST /token` returns ID+access+refresh; access token verifies via JWKS and carries `tenant_id`, `roles`, `groups`; `/userinfo`, `/introspect`, `/revoke`, logout all work.

## Phase 5 — Admin API
1. CRUD for users, tenants, memberships, roles/groups, OIDC clients; audit-logged; IdP-admin protected.
2. **Gate:** admin can register a client and create a user via API.

## Phase 6 — Integrate EDAMS as a client
1. Set EDAMS `AUTH_ISSUER`, `AUTH_JWKS_URI`, `AUTH_AUDIENCE`, `OIDC_CLIENT_ID/SECRET`, `OIDC_REDIRECT_URI`; `LOCAL_JWT_MOCK=false`.
2. Verify `POST /auth/callback` maps `roles`/`groups` → permissions via `idp_role_mappings` and JIT-provisions by email; adjust mapping if claim shape differs.
3. Frontend: redirect login to `GET /auth/oidc/authorize`; adjust `select-tenant`/`TenantSwitcher` per [IDP_TDD.md](IDP_TDD.md) §9.
4. **Gate (E2E):** log into EDAMS frontend → redirected to IdP → authenticate → land in dashboard with correct permissions; `resolveACL` gates a document correctly; multi-tenant user gets a tenant-scoped token; switch-tenant re-scopes.

## Phase 7 — Data migration (one-time)
1. Script copy of `User`, `Tenant`, `UserTenant`, `Role`, `UserRole` (+ MFA columns) from EDAMS DB → `edams_idp`.
2. **Dual-run window:** keep EDAMS local login behind a flag; document rollback.
3. **Gate:** an existing EDAMS user authenticates via the IdP with no re-registration; audit records `AUTH_LOGIN` on the IdP.

## Phase 8 — Deploy separately
1. Add `idp` service to a compose file (extend `docker-compose.dev.yml` or new `docker-compose.idp.yml`): own DB, Redis, port 4100; `Dockerfile` mirrors `backend/`.
2. Prod: subdomain `idp.<domain>` + TLS; secrets via secret store; JWKS rotation schedule; DB backups; health/readiness wired to orchestrator.
3. **Gate:** IdP reachable on its subdomain over TLS; EDAMS in prod authenticates through it; failover/backup verified.

## Phase 9 — Hardening & cutover
1. Load test token issuance; set NFR-3 latency budget.
2. Security review (PKCE, replay, rotation, lockout, revocation, audit immutability).
3. Retire EDAMS local login flag after the dual-run window.
4. **Gate:** security review passed; local login retired; `CURRENT-STATUS.md` updated with actual results.

## Rollback Runbook (summary)
- Re-enable EDAMS `LOCAL_JWT_MOCK`/local login flag.
- Point EDAMS back to its embedded auth (revert `AUTH_ISSUER` etc.).
- IdP DB retained; no destructive change to EDAMS user data during dual-run.

---

## Files this work will eventually touch (reference only)

**Port/reference (read):** `backend/src/modules/auth/auth.routes.ts`, `backend/src/shared/auth.ts`, `backend/src/config/env.ts`, `backend/src/config/permissions.ts`, `backend/src/modules/roles/roles.service.ts`, `backend/src/infrastructure/database/models/index.ts`, `backend/scripts/generate-rsa-keys.js`, `scripts/migrate.ts`, `scripts/seed-core.ts`.

**Create:** everything under `idp/`; `docs/idp/IDP_BRD.md`, `IDP_FRD.md`, `IDP_TDD.md`, `IDP_IMPLEMENTATION_PLAN.md`.

**Modify (integration phase):** `backend/src/config/env.ts` + `.env`, `backend/src/modules/auth/auth.routes.ts`, `frontend/app/(auth)/login/page.tsx`, `frontend/shared/components/TenantSwitcher.tsx`, `frontend/app/(auth)/select-tenant/page.tsx`, plus a compose service.

---

*Related: [IDP_BRD.md](IDP_BRD.md), [IDP_FRD.md](IDP_FRD.md), [IDP_TDD.md](IDP_TDD.md)*
