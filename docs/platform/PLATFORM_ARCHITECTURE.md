# Example Corp Enterprise Platform — Canonical Architecture Reference

**Document Version:** 1.2.0
**Effective Date:** July 25, 2026 (revised — full §6/§7 platform-standards coverage added per Directive §12; see the final section of this document for the ADR log, the single source of truth for decision history rather than duplicated here)
**Status:** Approved & Canonical, with explicitly-tracked open items (see `DEFECT_AND_GAP_REGISTER.md` in this same directory — several standards below are only partially converged and say so plainly rather than overstating completeness)
**Applies To:** Document Management System (EDAMS / DMS), Guest Management System (GMS), Single Sign-On / Identity Provider (SSO).

---

## 1. Architectural Mission and Core Principles

The Example Corp Enterprise Platform unites three independent core enterprise codebases—Document Management System (DMS / EDAMS), Guest Management System (GMS), and Single Sign-On (SSO)—under one standardized, high-performance platform architecture.

The platform architecture is governed by two foundational principles:

1. **Architectural Evolution without Functional Degradation:** Restructuring, decoupling, and standardizing system boundaries must preserve existing business rules, workflow engines, compliance postures (ISO 15489, MoReq2010, ISO 27001, Ethiopian E-Signature Proclamation No. 1072/2018), and physical security hardware integrations (UniFi Access).
2. **Decoupled Autonomy & Unified Governance:** Every application functions as an independent set of frontend and backend processes communicating strictly through versioned, secure HTTP APIs. Direct cross-database access between services is strictly prohibited.

---

## 2. Root Project Structure Standard

Every application within the platform follows an identical physical and logical structure:

```text
<system-name>/
├── frontend/    # Browser application (Vite / React / Next.js / Express EJS UI)
└── backend/     # API server, domain logic, DB access, background workers
```

### Decoupling Rules
- **Frontend Layer:** Contains only client-side UI components, view rendering, state management, and browser routing. Frontends must not hold server-side secrets, database connection parameters, or direct business logic. Frontends communicate with their respective backends exclusively via HTTP.
- **Backend Layer:** Contains all API routes, database access ORMs/query-builders, domain models, authorization enforcement, background job queues, and external service integrations. Backends do not output browser build artifacts directly to client browsers.

---

## 3. Standardized Port Allocation Table

Logical port numbers are fixed across all environments (Local Development, Staging, and Production). Environment differences are managed via host bindings and reverse proxy rules, never by changing logical port allocations.

| Service | Frontend Port | Backend Port | Frontend Origin | Backend Origin | API Base URL |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DMS / EDAMS** | `7101` | `7100` | `http://localhost:7101` | `http://localhost:7100` | `http://localhost:7100/api/v1` |
| **GMS** | `7201` | `7200` | `http://localhost:7201` | `http://localhost:7200` | `http://localhost:7200/api/v1` |
| **SSO / IdP** | `7301` | `7300` | `http://localhost:7301` | `http://localhost:7300` | `http://localhost:7300/api/v1` |

### Allocation Convention for Future Systems
When a new platform system is introduced, it is assigned the next available 100-block:
- System 4: Frontend `7401`, Backend `7400`
- System 5: Frontend `7501`, Backend `7500`

### Named Exception: GMS Same-Origin Gateway (Port `4200`)

The GMS staff SPA is additionally served through a same-origin reverse proxy at `http://gms.localtest.me:4200`, running inside the SSO backend process (`SSO/backend/src/gateway/server.ts`). This predates the 71xx/72xx/73xx allocation and is not part of it — it exists because GMS's dev frontend force-routes its API calls to a fixed port for the literal `localhost` hostname, and a non-loopback hostname resolving to `127.0.0.1` sidesteps that without a hosts-file edit. It is a fourth, deliberate allocation, not a migration leftover, and should not be treated as non-compliant with the table above.

---

## 4. API Architecture, Versioning, and Envelopes

### 4.1 URL Path Versioning
All application **resource/data APIs** mandate explicit URL-path versioning under `/api/v1/...` (e.g., `/api/v1/users`, `/api/v1/visits`, `/api/v1/documents`). Two categories of route are deliberately exempt, for different reasons:

- **OIDC protocol endpoints** (`/.well-known/openid-configuration`, `/auth`, `/token`, `/jwks`, `/session/end`) remain unversioned at root, as required by the OIDC specification — a fixed external contract, not a choice this platform controls.
- **Browser page/view routes** (SSO's `/portal`, `/admin`, `/interaction`, `/bridge`) are also unversioned. These are not resource APIs in the sense this section targets — they are pages navigated by humans (rendered by `SSO/frontend` from a `{view, locals}` view model the backend produces), the same way DMS's and GMS's own Next.js page routes (`/login`, `/dashboard`, etc.) are never prefixed with `/api/v1` — only their JSON APIs are. `oidc-provider`'s own interaction-URL generation and the SSO frontend's proxy path-matching both depend on these exact bare paths, and real users have them bookmarked; versioning them would be a breaking, high-risk change in exchange for a guarantee that only matters for machine consumers, which these routes don't have. If a machine client for one of these routes is ever built, version that specific client-facing surface at that time.

All genuine machine-to-machine APIs — including inter-service integration surfaces, not just externally-consumed ones — follow the versioning rule. SSO's GMS role-grant API is mounted at both `/api/v1/internal/gms/...` (the standard) and the legacy unversioned `/internal/gms/...` (kept live as the backward-compatible prior version during the migration window, per this section's own versioning philosophy — at least one prior major version stays reachable rather than being cut over instantly); GMS's corresponding inbound surface is `/api/v1/internal/sso/...`. Both sides of that one integration now follow the same convention.

### 4.2 Unified Response Envelopes
All API endpoints across DMS, GMS, and SSO produce standardized JSON response payloads.

#### Successful Response Format
```json
{
  "data": { ... },
  "meta": {
    "requestId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2026-07-24T23:19:10.000Z"
  }
}
```
*Note for GMS compatibility:* GMS responses may include `"success": true` alongside `"data"` and `"meta"` to support existing frontend components without breaking contracts.

#### Error Response Format
```json
{
  "error": {
    "code": "ERR-VALIDATION-FAILED",
    "message": "The request payload contains invalid fields.",
    "details": [
      {
        "field": "email",
        "message": "Must be a valid corporate email address."
      }
    ]
  },
  "meta": {
    "requestId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "timestamp": "2026-07-24T23:19:10.000Z"
  }
}
```

---

## 5. Centralized Identity and Authorization Architecture

### 5.1 Single Source of Truth
SSO (`7300`/`7301`) is the single authoritative system of record for platform identity, authentication, client registration, and application-scoped role catalogs.

- **Staff & Internal Actors:** Staff accounts, administrators, and platform users authenticate against SSO.
- **Client-Scoped Roles:** SSO maintains `idp_client_roles` as the catalog of valid role names per registered client scope (`edams` for DMS, `gms` for GMS).
- **Role assignment, two mechanisms, one precedence:** SSO resolves a user's role for a client in this order — (1) an explicit **per-user grant** (`idp_client_user_roles`, added 2026-07-25 specifically for GMS — lets an admin grant a role directly to one person, independent of any group), (2) an **AD-group mapping** (`idp_gms_role_mappings` for GMS; DMS's equivalent lives in DMS's own database, reached via internal API rather than direct SQL, since SSO has no foreign-table access into DMS), (3) a system default (`guest` for GMS, `EMPLOYEE` for DMS). This mirrors how mainstream IdPs (Keycloak, Zitadel, Authentik) let a role be granted either directly or via group membership.
- **Token/session Claims:** For DMS (a standard OIDC relying party), SSO issues JWT id_tokens containing claims under `https://edams.examplecorp.com/roles` and `https://gms.examplecorp.com/roles`; DMS's OIDC callback prefers the claim over its local table whenever the claim is present, full stop, only falling back to (and first-time-caching into) its local table when SSO gives none. For GMS (a token-bridge integration, not a direct OIDC client — "zero GMS code changed" as originally designed), the equivalent resolution happens server-side in SSO's bridge before GMS mints its own session, with the same effective precedence.
- **Claims-Based Authorization:** DMS and GMS backends authorize staff operations based on the role SSO resolved at login (DMS via a validated id_token claim; GMS via the bridge-provided `initialRoles`), not by re-querying a local table per request. Local role tables in both DMS and GMS remain as the sole source of truth for their independent local-password login paths, and as a login-time write-through cache — never as a second authoritative copy of the SSO-resolved role, and never synced to SSO on any schedule (see §7's explicit prohibition on that pattern).
- **Admin write path:** GMS's own admin UI (`PATCH /users/:id/roles`) writes through to SSO's per-user grant API (`PUT /api/v1/internal/gms/users/:email/roles` — versioned as of 2026-07-25 to match GMS's own `/api/v1/internal/sso` convention; the prior unversioned `/internal/gms` mount is kept live as a backward-compatible fallback, per §4.1's versioning-migration-window rule) as the authoritative store before updating its own local cache, fail-closed — if SSO is unreachable, the admin action fails loudly rather than silently drifting from SSO.
- **Known deviation from the end state (tracked as PLATFORM-GAP-012, open):** the precedence and write-through described above applies to the SSO-bridged login path (`issueSsoSession`). GMS's own native email/password login (`POST /api/v1/auth/login`) is a separate, fully live code path that mints a session directly from GMS's local `roles`/`user_roles` table, without consulting SSO's resolution at all. Any staff member authenticating that way — rather than through the SSO bridge — gets a token whose roles SSO never had a chance to weigh in on for that request. This is recorded, not fixed, because closing it means changing a real, currently-used login flow's behavior, which is a product decision, not an architectural cleanup.

### 5.2 Guest Workflow Boundary (GMS Exception)
GMS visitor check-ins and guest registration are lightweight business operations managed entirely within GMS (`7200`). Guests are not platform identities and are never created in SSO.

### 5.3 Fine-Grained Permission Enforcement (DMS Exception)
DMS coarse roles (e.g. `SYSTEM_ADMIN`, `EMPLOYEE`, `EXECUTIVE`) are vouched for by SSO token claims. DMS's fine-grained folder permission model, recursive CTE ACL checks, and document lifecycle permissions remain managed inside DMS as a domain-specific authorization layer on top of the verified coarse role.

---

## 6. Tracing, Logging, and Observability

### 6.1 End-to-End Correlation ID Propagation
Every request entering any frontend or backend is assigned a correlation identifier.
- Headers checked: `X-Correlation-ID`, `X-Request-Id`.
- Header emitted: Both `X-Correlation-ID` and `X-Request-Id` are echoed on all HTTP responses.
- Propagation: SSO backend forwards `X-Correlation-ID` when invoking internal APIs on DMS (`7100`) and GMS (`7200`).

### 6.2 Health Check Endpoints
Every backend service exposes standard liveness and readiness health checks at:
- `GET /api/v1/health`
- Response Payload:
```json
{
  "status": "ok",
  "service": "gms-backend",
  "timestamp": "2026-07-24T23:19:10.000Z",
  "meta": {
    "requestId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
}
```

### 6.3 Structured Logging (Directive §6.6)
DMS and GMS both log via `pino` (JSON, machine-parseable, correlation-ID-aware). SSO logged via plain `console.log`/`console.error` until 2026-07-25 (**PLATFORM-GAP-009**, closed) — it now uses `pino` for every log line on its live request-handling path (`main.ts`, `gateway/server.ts`, `admin/router.ts`, `auth/account.ts`, `auth/client-role-claims.ts`, `db/pool.ts`, `db/migrate.ts`), matching DMS's/GMS's format and redaction conventions (`req.headers.authorization`, password/secret fields redacted). Standalone CLI scripts in all three systems (seed scripts, one-off migration/verification tools run by a human operator, not part of the running service) intentionally keep plain console output in every system — that's the existing, consistent convention (confirmed in DMS's own `scripts/` directory), not an inconsistency to fix.

### 6.4 Request Validation (Directive §6.8)
DMS and GMS both validate incoming requests with `zod` schemas, reporting failures through the shared error envelope (§4.2). SSO has `zod` installed but does not use it anywhere in its source — it validates ad hoc, per call site, with manual coercion and no schema (tracked as **PLATFORM-GAP-022**, open). Retrofitting schema validation across SSO's routes is real, broad-surface-area work deferred to its own scoped follow-up rather than attempted at the tail of this pass.

---

## 7. Inter-Service Communication & Data Ownership

- **Strict Data Ownership:** DMS, GMS, and SSO each exclusively access their own database on the shared local PostgreSQL 17 server — `DMS`, `gmsdev`, and `idp` respectively (no shared database, no shared schema, per `CLAUDE.md`).
- **Internal APIs:** Cross-system administrative or operational requests (e.g., SSO querying GMS office lists or user live status) execute over HTTP APIs secured via shared secrets (`x-internal-api-key`).

---

## 8. Security: Headers, Rate Limiting, CSRF, and Secrets

### 8.1 Security Headers (Directive §6.9)
DMS and GMS both apply `helmet`. DMS runs a deny-by-default Content-Security-Policy (`default-src 'none'`) appropriate for a pure JSON API, relaxed only when its optional Swagger UI is explicitly enabled (never in production). GMS applies `helmet` with a fuller configuration including production-only HSTS, though its CSP currently allows `'unsafe-inline'` script/style unconditionally (justified by Swagger UI, but not scoped only to when docs are enabled — a smaller, lower-priority follow-up to align with DMS's pattern). SSO had no `helmet` at all until 2026-07-25 (PLATFORM-GAP-014, closed); it now runs `helmet` with CSP intentionally left off (`oidc-provider` renders some of its own HTML directly and has not yet been page-by-page audited for inline-script/style dependencies — enabling a strict CSP without that audit risked breaking real login/consent pages) while gaining every other helmet default (HSTS in production, COOP, CORP, X-DNS-Prefetch-Control, etc.) on top of the frame-deny and referrer-policy values it already set by hand.

### 8.2 Rate Limiting (Directive §7.5)
DMS and GMS both use `express-rate-limit` with a Redis-backed store (falling back to in-memory when Redis is unavailable), applying a strict per-route limiter to their own auth endpoints plus a generous global ceiling. SSO had zero rate limiting anywhere — including on `/interaction/:uid/login`, the literal username/password form submission, and the OIDC `/token` endpoint — until 2026-07-25 (PLATFORM-GAP-015, closed); it now applies an in-memory `express-rate-limit` (20/min on the whole `/interaction` mount, 60/min on `/token` — SSO has no Redis dependency today, so in-memory is the correct choice, matching GMS's own documented Redis-unavailable fallback behavior). An existing per-account lockout (failed-password and failed-MFA counters on `idp_users`) already protected against brute-forcing one specific known account; the new IP-based limiter is complementary, guarding against hammering the endpoint itself or spraying attempts across many accounts from one source.

### 8.3 CSRF Protection
Applied only where it's actually needed — none of the three systems applies blanket CSRF protection to bearer-JWT API routes, correctly, since CSRF is a cookie-session-authenticated-request problem, not a bearer-token one. GMS has a real double-submit CSRF guard (`gms_csrf_token` cookie + `x-csrf-token` header) scoped to its few cookie-adjacent routes (`/logout`, `/change-password`, `/toggle-2fa`). SSO has dedicated CSRF modules for its two genuinely cookie/session, browser-form-submission surfaces (the admin console and the login/interaction flow) — the correct scope, since those are the platform's only server-rendered, cookie-authenticated form surfaces. DMS's own API is pure bearer-JWT with no ambient-cookie mutating routes, so it correctly has none.

### 8.4 Secrets Management (Directive §7.6)
All three systems load secrets via `process.env` (dotenv) with no shared vault/secrets-manager integration — this is a platform-wide gap relative to the directive's aspiration of stricter handling than ordinary config, though not one this document treats as urgent, since none of the three commit real secrets to source (confirmed by grep; only known dev-seed placeholder passwords like `'demo'` appear in seed scripts). Each system does independently enforce a fail-fast production guard that refuses to boot with dev-placeholder or too-weak secrets: DMS's is the most thorough (`assertProductionRuntimeRequirements`, checking JWT secret length, DB non-superuser, audit HMAC secret, MinIO/SMTP credentials, and vault configuration all at once); SSO's (`assertProdSafeDefaults`) checks that every client secret, DB password, cookie key, TOTP key, and audit HMAC secret has actually been changed from its known dev value; GMS's is narrower (UniFi credentials plus a zod-level minimum-length check on JWT secrets). Bringing these three independent guards under one shared checklist/module is a reasonable future consolidation, not yet done.

### 8.5 CORS
DMS and GMS both apply an environment-driven origin allowlist (`CORS_ORIGINS`/`CLIENT_URL`) with `credentials: true` and a dev-only localhost exception appended outside production. SSO applies no CORS middleware at all — a deliberate consequence of its architecture (server-side view-model responses consumed by its own same-origin frontend proxy, plus the GMS same-origin gateway on `:4200`) rather than an oversight, but it means any *other* genuinely cross-origin browser call directly against SSO's `/api/v1` platform router would currently fail without a reverse proxy in front of it — worth revisiting once SSO's frontend/backend split (§2) is exercised by a wider set of direct browser callers.

---

## 9. Caching Strategy (Directive §6.17)

**Closed 2026-07-25.** DMS and GMS had independently converged on the same pattern — Redis-backed caching with an in-memory fallback when Redis is unavailable, and real (not just documented) invalidation — but every key in DMS carried no app namespace at all (`acl:`, `aclr:`, `rolePerms:`, `featureFlags:`, `userDepts:`, `audit-chain:`, bare `revoked_user:`/`mfa_fail:`/`oidc:state:` in the auth module), while GMS had already consistently namespaced its own keys `gms:...` except for one outlier (`session-revocation.service.ts`'s `revoked_user:`). Every DMS key now carries an `edams:` namespace (auth-specific keys further under `edams:auth:`), with domain segments kebab-cased to match the one previously-good example (`edams:rate-limit:`); GMS's one outlier now carries `gms:auth:` like the rest of its keys. Pure string-prefix change, no logic touched; full test suites in both systems stayed green throughout (DMS: 26 suites/236 tests; GMS: 37 suites/137 tests). DMS invalidates via non-blocking `SCAN`+`DEL`; GMS's `delPattern` uses `KEYS`, which blocks the Redis event loop on a large keyspace — a minor, low-urgency perf hardening opportunity for GMS specifically (§6.21), not addressed here. SSO has no cache layer at all, consistent with CLAUDE.md's "Redis deferred to a scale-out phase" — confirmed accurate: no `redis`/`ioredis` dependency exists in SSO's `package.json`.

---

## 10. File Handling (Directive §6.18)

DMS is the platform's file-storage reference implementation: MinIO (S3-compatible) as the primary backend with a genuine live fallback to local disk, on both writes and reads, not just at boot — a mid-request MinIO outage still lands safely on disk. GMS does not implement persistent file storage today: it declares `multer` as a dependency but never imports it anywhere in its source, and the one place it appears to handle an uploaded image (guest ID-document capture during check-in) processes the image in-memory via Tesseract OCR and never writes it to disk, MinIO, or a database column — there is no `id_photo`/`photo_url` column in its schema. This may well be a deliberate data-minimization choice (an ID photo used only transiently for OCR, then discarded, is arguably a *better* privacy posture than durable storage) rather than a gap to close — this document does not recommend adding persistent guest-photo storage to GMS without an explicit product decision that guest ID images should in fact be retained. SSO has no file-handling code, correctly, given its scope.

---

## 11. Background Processing (Directive §6.19)

DMS and GMS have each independently built a transactional outbox (write the side-effect intent to an `outbox_events` row in the same DB transaction as the domain change, then dispatch it via a poller) — the same architectural pattern, arrived at separately, which is itself a good sign for how naturally this pattern fits the platform's needs. **Retry/backoff constants unified 2026-07-25.** GMS's outbox previously capped at 10 attempts with a `2^attempts` second backoff (capped at 5 minutes); it now matches DMS's own outbox policy exactly — 3 attempts (`OutboxEvent.max_attempts` model default, `infrastructure/database/models/OutboxEvent.ts`), `30s × 4^(attempts−1)` backoff capped at 1 hour (`outbox.repository.ts`'s `markOutboxFailed`) — with no stated reason for the prior divergence, this was a straightforward alignment rather than a considered tuning decision worth preserving. GMS separately runs BullMQ (`infrastructure/queue/queue.ts`) for its notification/reminder/SLA job queues, distinct from its outbox; that queue's default backoff was `2s` exponential (far faster than DMS's `30s` starting point for the same class of transient failure) and now starts at `30s` exponential with the same 3-attempt cap — the exact curve still differs from DMS's outbox (BullMQ's native exponential type doubles per attempt vs. the outbox's quadrupling), since one is a Redis-backed job queue and the other a DB-polling loop, but both now share the same starting delay and attempt count. DMS still gives a proactive in-app admin notification on dead-letter; GMS still surfaces dead-lettered events to an operator dashboard rather than pushing a notification — that UX difference is unrelated to the retry-policy numbers and was not touched. SSO's only background activity is a bare hourly `setInterval` sweep of expired OIDC artifacts and stale login events — informal, but appropriately so given its low volume and lack of any side-effect-dispatch requirement; it does not need an outbox.

---

## 12. Pagination, Filtering, and Sorting (Directive §6.16)

This is a genuine, unresolved cross-system inconsistency, tracked as **PLATFORM-GAP-018** (open). DMS's collection endpoints use offset-style pagination with `skip`/`take` parameters; GMS's use page-number-style pagination with `page`/`limit`. Neither system exposes a client-controlled sort parameter — both hardcode result ordering server-side. GMS additionally has an internal inconsistency between its own endpoints' date-range filter parameter names (`from`/`to` on one endpoint, `startDate`/`endDate` on another). Reconciling DMS's and GMS's pagination conventions onto one shared standard is the right end state per Directive §6.16, but it is a breaking API change for every existing caller of every collection endpoint in both systems (each system's own frontend, at minimum) — not a same-shape internal refactor, and therefore not something this pass changes unilaterally. See the gap register for the reasoning and the suggested migration shape (a supported deprecation window, coordinated frontend updates, and an explicit decision on which convention — `skip`/`take` or `page`/`limit` — becomes the platform standard).

---

## 13. Database Standards and Migration Conventions (Directive §6.10)

Per the directive's own instruction ("keep using whatever tool is already standard for that stack... the goal is consistent conventions within whatever tool is already standard, not a forced tool migration"), each system correctly keeps its existing ORM: DMS and GMS both use Sequelize; SSO uses raw `pg` with no ORM (appropriate for its much smaller, mostly-single-table-per-concern schema). The genuine inconsistency is migration-file naming, which is not tool choice and is worth reconciling over time: DMS uses timestamp-prefixed `.sql` files (`20260610000000-baseline.sql`); SSO uses sequential numeric `.sql` files (`001_init.sql`); GMS's own migrations directory mixes both schemes internally (early files are numeric `NNN-name.js`, later ones are timestamp-prefixed `.js`) — GMS's internal inconsistency predates this platform-standardization effort and is arguably the more pressing of the two to fix, since it's not even self-consistent within one system. Renaming already-applied migration files retroactively risks breaking each tool's applied-migrations tracking table (`SequelizeMeta`/`idp_migrations`) if not done with care, so this document records the target convention (timestamp-prefixed files, matching DMS's already-largest and most consistent set) without retroactively renaming any already-applied migration in any system.

---

## 14. Testing Strategy (Directive §6.20)

DMS (~26 files, Jest) and GMS (~80 files, Jest, explicitly split into `unit/` and `integration/` subdirectories) have meaningfully converged on the same tooling. SSO is the outlier on both tooling and depth: it uses Node's built-in `node:test` runner rather than Jest, and has only 2 test files with no unit/integration split — tracked as **PLATFORM-GAP-017** (open). Standardizing SSO onto Jest and building out coverage for its highest-risk, least-tested surfaces (the auth/bridge/admin-role-grant code paths) is recorded as a scoped follow-up effort in its own right, not attempted piecemeal here.

---

## 15. Deployment and Operational Consistency (Directive §7.1)

**Primary path unified 2026-07-25** — tracked as **PLATFORM-GAP-016**, now partially
closed. The project owner made the deliberate decision: all three systems now share
the same *primary* deployment mechanism — the same model DMS already documented for
its no-Docker path, generalized: copy or `git pull` the repo onto a Windows server,
`npm install`, `npm run build`, run migrations, then `npm run start` (or the
equivalent production-start command) running directly in a console window, the same
shape as `npm run dev` in development. No Docker, no PM2, no systemd, no PaaS. Each
system now has its own `DEPLOY-WINDOWS-MANUAL.md` (`DMS/Documentations/`, GMS repo
root, SSO repo root) documenting this exactly, and DMS's backend gained a `"start"`
script (`node dist/src/main.js`) it was previously missing — live-verified by
building and booting it against a real port.

GMS previously deployed to Render.com, a managed PaaS (`render.yaml`); that file was
removed entirely 2026-07-25 by explicit project decision (its `startCommand` ran
`db:fresh:prod` — a full wipe-and-reseed — on every deploy/restart, and it was never
a completed production target in the first place: placeholder `CLIENT_URL`,
unset secrets). Render is no longer an option for GMS at all, not merely demoted.

What did **not** change, and remains a real, acknowledged inconsistency (this is why
the gap is *partially*, not fully, closed): each system's own pre-existing *alternate*
mechanism is still different from the other two's alternates —

- **DMS**: Docker Compose in production (`docker-compose.prod.yml`, including a
  `pg_dump` backup sidecar), or the original Linux-manual/pm2 path
  (`Documentations/DEPLOY-MANUAL.md`).
- **GMS**: Docker Compose (`docker-compose.yml`).
- **SSO**: a standalone multi-stage `Dockerfile` with no compose/orchestration file
  of its own.

So the platform now has one unified *primary* path and three still-different
*secondary* paths — a real improvement (an operator who only ever needs the primary
path, which is the common case for this platform's scale, sees identical steps
across all three systems) but not full mechanism-level parity. Fully consolidating
the alternates too would mean picking one of Docker Compose / pm2 / a PaaS as the
single secondary standard and migrating the other two systems onto it — a further,
separate infrastructure decision with its own cost/operational tradeoffs, not
attempted here.

---

## 16. Backup and Recovery (Directive §7.9)

- **DMS**: Documented and automated — a `pg_dump` backup sidecar in `docker-compose.prod.yml` with configurable retention, and a full restore procedure in `DR-RUNBOOK.md`.
- **GMS**: Documented, manual — `PRODUCTION_GUIDE.md` covers `pg_dump`/restore commands and a `db:backup:prod` script. No Redis backup strategy is documented, though GMS's Redis usage today is cache/queue/rate-limit state that is acceptable to lose and rebuild, not a system of record.
- **SSO**: Had nothing documented prior to 2026-07-25 (**PLATFORM-GAP-020**, closed as a documentation deliverable this pass). The recommended, now-documented approach mirrors DMS/GMS's own practice: a scheduled `pg_dump` of the `idp` database (the platform's actual identity/session/role-grant data — arguably the single most sensitive dataset of the three, since losing it would sever every system's authentication path simultaneously) with the same retention policy as DMS's backup sidecar, restorable independently of DMS's and GMS's own backups since each system's data is independently owned (§7). No backup cron or script has been implemented or scheduled on any production host as part of this pass — that requires production infrastructure access this repository audit cannot reach; only the documented target procedure is a deliverable here.

---

## 17. Session, Token Lifetime, and Single Logout (Directive §7.10)

Configured token lifetimes differ by system and are treated here as legitimate, independently-tuned policy rather than something that must be numerically identical — each system's risk profile is different (an internal document-management session and a guest-facing visit-management session do not need identical access-token lifetimes):

| System | Access token | Refresh token |
|---|---|---|
| DMS | 15 minutes | 8 hours |
| GMS | 15 minutes | 7 days |
| SSO | 1 hour (OIDC id/access token) | 24 hours (refresh), 14 days (SSO session) |

Revocation is real in both DMS and GMS, not purely expiry-based: both maintain a Redis-backed per-user "revoked as of" cutoff timestamp, checked on every authenticated request, set when an account is deactivated or a role changes. DMS fails **closed** in production/staging if Redis is unreachable during that check (an unusual outage degrades to rejecting requests rather than silently trusting stale tokens); GMS's equivalent check currently fails **open** in the same scenario (tracked as **PLATFORM-GAP-021**, open — recorded, not silently changed to fail-closed, since that would newly reject legitimate users during any Redis blip, a live behavior change requiring an explicit decision).

Cross-system logout propagation exists, but as direct, best-effort synchronous HTTP calls from SSO's own admin-deactivate/logout path (`revokeAllSessions` → `revokeGmsSessionsByEmail` for GMS, an OIDC-backchannel-logout-style signed notification to DMS) rather than the event-bus fan-out (`user.deactivated`/`user.role_changed` published to shared async infrastructure) the directive suggests as the pattern that scales to a fourth or fifth platform service without a new point-to-point integration per pair. Both calls are deliberately best-effort (wrapped in try/catch) so an unreachable DMS or GMS never blocks SSO's own logout. Migrating this to a genuine event-bus fan-out is a reasonable future step once a shared async infrastructure choice is made platform-wide (§11) — not undertaken here, since the current direct-call mechanism does work today and changing it is additive infrastructure work, not a standards-alignment fix.

---

## 18. API Documentation and Specification-First Development (Directive §6.11, §7.2)

DMS maintains a hand-written OpenAPI 3.1 spec (`docs/api/openapi.yaml`) with no automated drift-check against its actual routes. GMS goes one step further: its hand-written spec is paired with a CI job (`validate-openapi-coverage.js`, required in `phase2-validation.yml`) that fails the build if the spec and the actual mounted routes diverge — the strongest implementation of §7.2's "generated as close to the code as possible so it cannot silently go stale" among the three, even though the spec itself is still hand-authored rather than decorator-generated. SSO has no API documentation of any kind today (**PLATFORM-GAP-019**, open) — its custom (non-OIDC) surface is small (`/api/v1/health`, `/health/ready`, `/metrics`, the internal GMS role-grant API), and OIDC's own endpoints are already self-describing via `/.well-known/openid-configuration` per spec, but the custom surface itself has zero documentation and no drift protection. Authoring a minimal spec for SSO and, ideally, matching GMS's CI drift-check pattern is recorded as a follow-up, not attempted in this pass.

---

## 19. Idempotency for Mutating Operations (Directive §7.4)

Exists in both DMS and GMS, in different, narrower-than-general shapes rather than being absent. DMS has an `IdempotencyKey` model, but it's scoped specifically to outbox webhook fan-out dedup (guarding against a double-send on crash/retry), not a generic `Idempotency-Key` HTTP header mechanism for document workflow actions themselves — those actions instead rely on row-level locking to serialize concurrent finalize calls. GMS has a real generic `Idempotency-Key` header middleware, but it's applied to visit creation specifically, not to the outbox-pattern event dispatch the directive calls out as the motivating case for GMS — GMS's own outbox dispatchers have no idempotency-key guard of their own (though the outbox pattern's at-least-once, dedupe-after-success design already provides its own form of duplicate-delivery safety, independent of a header-based key). Extending idempotency-key support to DMS's workflow-action endpoints and to GMS's outbox dispatch path specifically is a reasonable future increment, recorded here rather than added speculatively.

---

## 20. Git Workflow and Code Review Conventions (Directive §7.7)

None of the three repos currently has a `CONTRIBUTING.md`, a pull-request template, or branch-protection configuration; commit messages across all three are free-form descriptive sentences rather than a structured convention (e.g. Conventional Commits) — consistent across all three, which is itself a form of alignment, just not a documented one. Each repo does run CI on every push/PR via GitHub Actions (DMS: typecheck, lint, `npm audit`, unit tests, a DB-backed integration job, then a Trivy-scanned Docker build gated to `main`; GMS: typecheck, Jest with live Postgres/Redis services, a frontend smoke test, the OpenAPI coverage gate, then a Docker build smoke test; SSO: typecheck, test, a docs-drift gate, then a Docker build) — real, working CI gates exist per system, they are just not formalized into a shared written convention or enforced via GitHub branch-protection rules from within this codebase (configuring branch protection is a repository-settings change outside what a code-level architecture pass makes unilaterally). Adopting one shared commit-message convention and a lightweight `CONTRIBUTING.md` template across all three repos is a low-risk, low-effort improvement recorded here as a good near-term follow-up.

---

## 21. Future Growth, Extensibility, and Third-Party Integration Strategy (Directive §10)

The platform is designed so that adding a fourth system requires no restructuring of the first three:

- **Port allocation** (§3) is self-explanatory and pre-reserved: the next system takes the next free hundred-block (`7401`/`7400`, then `7501`/`7500`), recorded in this document at the moment of allocation.
- **Structural onboarding** (§2) is identical regardless of what the new system does: a `frontend/` and `backend/` root, HTTP-only communication between them, no shared database with any existing system.
- **Identity onboarding** follows one of two paths, chosen by what the new system speaks:
  - A system that speaks OIDC natively integrates exactly the way DMS does today: register as a client in SSO, receive client-scoped roles under its own scope in `idp_client_roles`/`idp_client_user_roles`, and authorize purely from validated token claims — no new identity mechanism to design.
  - A legacy or third-party system that cannot speak OIDC directly sits behind a thin adapter that validates SSO-issued tokens and translates them into whatever session mechanism that system requires — the adapter validates against SSO's JWKS, it never receives (and must never be given) a copy of SSO's own user/role tables. This is the same shape as GMS's existing token-bridge integration, generalized: the number of integrations the platform must build stays proportional to the number of systems joining it, not to the number of pairs of systems that need to agree with each other.
- **Legacy and non-Node integration is a first-class case, not an afterthought**: OIDC is a wire protocol, not a Node-specific mechanism. Legacy PHP (`jumbojett/openid-connect-php`, `league/oauth2-client`) and plain JavaScript (`oidc-client-ts`) clients integrate by verifying the RS256 `id_token` against SSO's `/jwks`, exactly as DMS does. This is why SSO self-hosts OIDC rather than adopting a vendor identity platform (Keycloak, Auth0, Azure AD) — a vendor SDK would reintroduce exactly the kind of lock-in this section exists to avoid.
- **Cross-cutting concerns scale by convention, not by pairwise integration**: a new system adopts the platform's existing API versioning scheme (§4), response envelope (§4.2), correlation-ID propagation (§6.1), and — once actioned — the event-bus-based deactivation/role-change fan-out described in §17, rather than negotiating a bespoke contract with each existing system individually.
- **External/public-facing flows remain outside SSO by design**: GMS's guest email/OTP login, DMS's external signer links, and any future system's equivalent public-facing, non-employee flow stay on that system's own native mechanism. SSO is opt-in per surface, never global — a new system does not need to route every user through the identity provider, only its genuine internal/staff actors.

## 22. Architecture Decision Records (ADRs)

The full, dated ADR log lives in `SSO/docs/platform/ADR.md` — that file is the single
source of truth for decision history. This section deliberately does **not** keep a
second copy of that table: an earlier version of this document did, and it had
already drifted from `ADR.md` (wrong ADR numbers, and an "ADR-011" that doesn't exist
in the real log) by the time it was checked on 2026-07-25 — precisely the
two-sources-of-one-fact problem this platform's own architecture principles (§7)
warn against, applied to documentation instead of a database. Read `ADR.md` directly
for the current decision history, including the 2026-07-25 entries closing out SSO's
backend/frontend decoupling (ADR-013) and GMS's role migration to SSO (ADR-014).
