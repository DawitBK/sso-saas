# Architecture Decision Record

## ADR-001 — Standard platform port blocks

**Date:** 2026-07-24  
**Decision:** DMS uses 7100/7101, GMS uses 7200/7201, and SSO uses 7300/7301; the backend gets the even port and frontend the matching odd port.  
**Why:** The allocation makes ownership and the browser/API boundary self-evident, removes collisions with common local defaults, and leaves a predictable range for future services.  
**Compatibility:** Old local defaults are migrated by configuration, with client URLs, OIDC redirect URIs, and back-channel destinations updated together.

## ADR-002 — Path-versioned application APIs

**Date:** 2026-07-24  
**Decision:** Application APIs use `/api/v1`; OIDC protocol endpoints retain their standards-defined paths.  
**Why:** URL versioning is immediately visible to clients and supports a future compatibility window without coupling unrelated resources or services to the same breaking release.

## ADR-003 — SSO is the identity authority, not a cross-database administrator

**Date:** 2026-07-24  
**Decision:** SSO owns identity and client-scoped role data. Other services consume signed claims and expose authenticated APIs for service-owned administrative behavior.  
**Why:** Direct database access produces duplicated authority, bypasses service invariants, and prevents independent recovery and deployment. HTTP contracts preserve ownership while allowing local admin surfaces to remain familiar.

## ADR-004 — GMS sessions are issued only by GMS

**Date:** 2026-07-24  
**Decision:** The SSO-to-GMS bridge calls authenticated internal GMS session creation and session-revocation endpoints. GMS provisions a first-time user, preserves its own role and account-state decisions for existing users, signs its own tokens, and stores/revokes its own refresh sessions.  
**Why:** The former bridge required SSO to connect to the GMS database and possess GMS JWT secrets. Moving the narrow operation behind GMS's API preserves the browser handoff and single-logout behavior without bypassing GMS invariants or coupling the IdP to its schema.  
**Compatibility:** The public GMS auth API and the existing one-time gateway handoff are unchanged. The internal API is disabled unless its distinct shared service key is configured.

## ADR-005 — SSO admin console reads DMS and GMS state only through internal APIs

**Date:** 2026-07-24  
**Decision:** The SSO admin console no longer reads DMS or GMS state through foreign database pools for day-to-day administration. DMS now exposes shared-secret internal endpoints for DMS role mappings, mapped-group discovery, and live user status; GMS exposes shared-secret internal endpoints for office lookup and live user status. The SSO admin console consumes those APIs instead of querying `users`, `roles`, `user_roles`, or `offices` tables directly.  
**Why:** Even read-only cross-database access couples SSO to foreign schemas and bypasses the authoritative service contract. Moving these reads behind the owning backend keeps office scoping, role materialization, account-active semantics, and future audit or validation logic inside the service that owns them.  
**Compatibility:** The SSO admin UI and form flows stay unchanged. The remaining migration work is live end-to-end verification of those internal-admin flows and the later split of SSO into independent frontend/backend deployables.

## ADR-006 — Remove dormant foreign-database pool modules from SSO

**Date:** 2026-07-24
**Decision:** The obsolete `src/db/dms-pool.ts` and `src/db/gms-pool.ts` modules, along with their unused `DMS_DATABASE_URL` / `GMS_DATABASE_URL` SSO config surface, are removed now that the runtime and admin paths use internal DMS/GMS APIs.
**Why:** Leaving dormant cross-service database connectors in the repository invites regression and misleads operators about which configuration is still required. Removing them makes the current ownership boundary explicit in both code and documentation.
**Compatibility:** Active SSO flows already use `DMS_API_BASE_URL`, `DMS_INTERNAL_API_KEY`, `GMS_API_BASE`, and `GMS_INTERNAL_API_KEY`. The remaining impact is limited to developers who were still relying on the obsolete pool modules in ad hoc local scripts.

## ADR-007 — Move SSO browser templates into `SSO/frontend`

**Date:** 2026-07-24
**Decision:** The SSO login, consent, portal, security, and admin EJS templates now live under `SSO/frontend/src/views`, while `SSO/backend` renders that source in development and copies it into `dist/views` during build.
**Why:** This creates a real frontend source boundary without forcing an unsafe rewrite of the OIDC and admin flows. It is the smallest structural step that moves SSO toward the directive's required `frontend/` and `backend/` split while preserving the current server-rendered behavior.
**Compatibility:** Route behavior and rendered pages stay the same. The Docker build runs from the `SSO/` root so the backend image can include both `backend/` and `frontend/` sources.

## ADR-008 — Rename SSO runtime root to `SSO/backend`

**Date:** 2026-07-24
**Decision:** The former `SSO/identity/` runtime root is renamed to `SSO/backend/` so SSO matches the same `frontend/` + `backend/` repository layout already used by DMS and GMS.
**Why:** The directive requires every platform application to expose the same root structure. Renaming the runtime root makes ownership and deployment boundaries explicit without changing OIDC, admin, portal, or bridge behavior.
**Compatibility:** Local dev commands, Docker build context, and CI now reference `SSO/backend`. The EJS UI remains server-rendered on port 7300 until a separate 7301 browser client is introduced.

## ADR-009 — Independent SSO browser process on 7301

**Date:** 2026-07-24
**Decision:** Add `SSO/frontend` as an independently runnable Express proxy on port 7301. It forwards all browser traffic to `SSO/backend` on 7300 over HTTP. The public OIDC issuer (`IDP_ISSUER`) is the frontend URL; server-side token and JWKS calls use `IDP_INTERNAL_URL` on the backend port.
**Why:** This satisfies the platform port allocation (7301 browser / 7300 API) and creates a real process boundary without rewriting the existing EJS/OIDC interaction flow in one step.
**Compatibility:** Backend-only direct access on 7300 remains available for service-to-service calls. Browser flows and OIDC `iss` claims use 7301 when configured as documented in `.env.example`.

## ADR-010 — Client-scoped role catalog in SSO

**Date:** 2026-07-24
**Decision:** Introduce `idp_client_roles` as the SSO-owned catalog of roles per relying party (`gms`, `edams`). Seed GMS's six staff roles (including the previously missing `super_host`) and DMS's seven coarse roles. The SSO admin console reads role dropdowns from this catalog instead of hardcoded arrays. Guest remains excluded (GMS business record, not an SSO identity).
**Why:** Directive §6.3 requires SSO to own client-scoped role definitions so DMS/GMS authorize from claims rather than drifting local catalogs. Establishing the catalog first is the safe prerequisite before migrating grants into tokens and retiring GMS-local role authority.
**Compatibility:** Existing `idp_gms_role_mappings` and DMS internal role-mapping APIs are unchanged. GMS still authorizes from its own `roles` / `user_roles` tables until a later claims-based migration step. Admin UI now offers `super_host`, matching GMS's live staff role set.

## ADR-012 — Additive client-scoped role claims on SSO tokens

**Date:** 2026-07-24
**Decision:** SSO id_tokens and userinfo now carry additive client-scoped role claims derived from existing group→role mappings: `https://gms.examplecorp.com/roles` (from `idp_gms_role_mappings`) and `https://edams.examplecorp.com/roles` (resolved through DMS's internal `POST .../role-mappings/resolve`). GMS SSO session minting prefers SSO-supplied roles in the session JWT for both first-time and returning users without rewriting local role tables. DMS OIDC callback prefers edams role claims from the verified id_token for all SSO logins (returning users included); local `user_roles` are written only on first provision. Local role tables remain for password-login and admin UI until retirement.
**Why:** Directive §6.3 requires the JWT SSO issues for an application to carry that application's roles as claims, and requires consumers to authorize from validated claims rather than drifting local catalogs. Emitting claims from the mappings already in production is the safe additive step before deleting any local authority.
**Compatibility:** Existing `ad_groups` claim unchanged. GMS/DMS password-login still read local tables. A lone SSO `guest` fallback never demotes an existing GMS staff account that already has local roles. Live-verified with `assert-role-claims.mjs`, `assert-dms-returning-claims.mjs`, and `assert-gms-returning-sso-roles.mjs`.

**Correction (2026-07-25):** The claim above that GMS session minting "prefers SSO-supplied roles... for both first-time and returning users" did not hold up against a direct read of `GMS/backend/src/modules/auth/auth.service.ts`'s `issueSsoSession()` — for any already-provisioned existing user, GMS's local role won over SSO's. See SSO-GAP-004 in `DEFECT_AND_GAP_REGISTER.md` and ADR-014 below for the actual fix. Recorded here rather than silently edited so the discrepancy itself is on the record.

## ADR-013 — Complete SSO backend/frontend decoupling (remove the direct-render fallback)

**Date:** 2026-07-25
**Decision:** `SSO/backend/src/http/view-model.ts`'s `viewModelMiddleware` no longer branches on an `X-SSO-UI` header or `Accept` type — every `res.render(view, locals)` call site always returns the JSON `{ view, locals }` view model. `SSO/backend/src/main.ts` no longer sets an Express view engine or views directory. `SSO/backend/package.json` no longer depends on `ejs` and no longer copies `SSO/frontend/src/views` into its own `dist/` at build time.
**Why:** ADR-007 through ADR-009 introduced the frontend/backend split incrementally but deliberately left the backend able to render full HTML directly, as a transitional fallback ("during the migration," per `view-model.ts`'s prior doc comment). That fallback was still reachable by any direct hit to `:7300` and the build-time view-copy was a real build-level coupling the directive's §3 forbids ("completely decoupled at the process, build, and deployment level"). Since `SSO/frontend` has had its own independent EJS rendering (`ejs.renderFile` against its own `src/views`) since ADR-009, nothing legitimate ever needed the backend's fallback path once the frontend proxy was in place — removing it closes the gap with no functional change for real traffic.
**Accepted exception, not fixed:** `oidc-provider`'s `rpInitiatedLogout.logoutSource` (`SSO/backend/src/oidc/provider.ts`) still renders a small inline HTML string directly from `:7300` on `/session/end`. This is library-owned rendering (like OIDC's other protocol endpoints keeping their spec-mandated paths unversioned), not SSO's own app UI — left as-is rather than migrated, given the low value of touching library-internal rendering for one small logout-confirmation page.
**Compatibility:** No behavior change through the frontend (`:7301`) — confirmed live via `assert-view-model-split.mjs` and `live-login.mjs`, both PASS. Direct hits to the backend (`:7300`) that used to render full HTML now return the JSON view model instead; the only intended consumer of those routes is the frontend proxy, which already always requested the JSON form. **Production topology dependency**: whatever reverse proxy serves the public SSO hostname must point at the frontend (`:7301`), not the backend (`:7300`) — `SSO-OPERATIONS.md` still describes the pre-split single-process topology and needs a refresh pass; this could not be verified from the repo alone since the production reverse-proxy config lives outside it.

## ADR-014 — SSO becomes the role system-of-record for GMS via per-user grants (§6.3 migration, GMS side)

**Date:** 2026-07-25
**Decision:** Add `idp_client_user_roles` (migration `009_gms_role_grants.sql`) — a per-user, per-client role grant table in SSO, validated against the existing `idp_client_roles` catalog (migration 008, which explicitly anticipated this as its own follow-up). GMS role resolution at bridge-login time (`resolveGmsRoles` in `client-role-claims.ts`) now checks this table first, then the existing AD-group mapping (`idp_gms_role_mappings`), then defaults to `guest` — exactly mirroring the "grant directly to a person, or via group membership" pattern named in the directive's own reference to Keycloak/Zitadel/Authentik. A new inbound internal API, `PUT`/`GET /internal/gms/users/:email/roles` (gated by `SSO_ROLES_API_KEY`, the mirror-image secret of the existing `GMS_INTERNAL_API_KEY`-gated outbound direction), lets GMS's own admin endpoint (`PATCH /:id/roles`) write through to SSO as the authoritative store before touching its own local `user_roles` cache, fail-closed.
**Why:** The previous state (ADR-012) had SSO's group-mapping resolution already correctly winning over GMS's local table whenever it had a real (non-default-`guest`) opinion — but almost no GMS staff have an AD group mapped, so SSO's resolution defaulted to `guest` for nearly everyone, which GMS's existing precedence logic correctly treats as "don't demote an already-provisioned user" — meaning GMS's local table won by default, not by bug. The actual gap was that SSO had no way to express "grant this specific person a role" outside of AD-group membership; adding that mechanism closes it. **GMS's `issueSsoSession` precedence math needed zero code changes** — it was already correct once SSO had a real opinion to offer.
**Migration safety:** Every GMS user's current local role was backfilled into the new SSO table (`scripts/backfill-sso-role-grants.ts`) and independently verified row-for-row (`scripts/verify-sso-role-grants.ts`, 248/248 matched against the live `gmsdev` dev database) *before* anything depended on the new table, per the directive's explicit §6.3 migration-order requirement and its distrust of a migration script's own exit code as sufficient evidence.
**What deliberately did not change:** `guest` is excluded from the new grants table (matches migration 008's own comment that guest is a GMS business record, not an SSO identity) — an admin setting a user's role to guest-only clears their SSO grant rather than being rejected. GMS's fully independent native email/password login path is untouched; the local `user_roles` table remains the correct, sole source of truth for accounts authenticating that way. No database-level sync job of any kind was introduced — resolution reads SSO's table live at login time, and the local table is a one-directional (SSO→GMS) write-through cache written only at admin-grant time, not a second authoritative copy (see §6.3's explicit warning against exactly that).
**Compatibility:** Live-verified end to end with `SSO/backend/test-scripts/assert-role-grant-precedence-live.mjs` (changed a real user's role via SSO alone, confirmed GMS's minted session JWT reflected it while GMS's local table stayed unchanged) and a fail-closed test (SSO unreachable → the write throws rather than silently degrading). GMS's full Jest suite (36 suites / 131 tests) passes, with one existing unit test's mocks updated for the new outbound call. Zero changes to `rbac.middleware.ts`, `roles.ts`, or any of GMS's 14 RBAC-guarded route files — they only ever read `req.userRoles` off the already-minted JWT, which is unaffected by where that JWT's roles were sourced from.
