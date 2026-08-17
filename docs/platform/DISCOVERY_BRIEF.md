# Platform Discovery Brief

**Date:** 2026-07-24  
**Scope:** EDAMS/DMS, GMS, and SSO

## Starting topology

| System | Repository root | Frontend | Backend | Current local ports |
| --- | --- | --- | --- | --- |
| EDAMS / DMS | `DMS/` | Next.js in `frontend/` | Express 5 / TypeScript in `backend/` | 3000 / 4000 |
| GMS | `GMS/` | Next.js in `frontend/` | Express 5 / TypeScript in `backend/` | 5001 / 5000 |
| SSO | `SSO/backend/` + `SSO/frontend/` | EJS views rendered by the frontend process from backend JSON view models; OIDC/API proxied to backend | Express 5, `oidc-provider`, PostgreSQL in `backend/` | 7300 backend (+ gateway 4200); **7301** browser entry |


DMS and GMS already have the required process and source-tree separation. Both use `/api/v1`, have independently owned PostgreSQL databases, and retain their existing asynchronous integrations: DMS uses Redis, BullMQ, MinIO, Meilisearch, Socket.IO, and a transactional outbox; GMS uses Redis, BullMQ, Socket.IO, UniFi Access, and an outbox worker. No frontend directly accesses either database.

SSO is an OIDC provider with discovery, JWKS, authorization, token, interaction, portal, administrative, session, and GMS bridge functionality. Its user-facing EJS portal, consent, interaction, and administration pages are currently mounted inside the same Express process as the identity-provider protocol endpoints. This is the primary frontend/backend separation gap.

## Coupling inventory

* DMS is an OIDC relying party. It validates issuer, audience, and JWKS configuration, supports authorization-code login, and accepts a signed back-channel logout notification.
* GMS currently consumes the IdP through a compatibility token bridge. The bridge provisions or matches GMS users and mints a GMS-compatible token. Guest registration remains a GMS-only business flow and is not an SSO identity flow.
* SSO originally had direct DMS and GMS database pool modules. Those active paths are replaced by authenticated internal service APIs; the dormant pool modules have been removed. Admin clickthrough on 2026-07-24 confirmed the HTTP boundary end to end.
* SSO also calls DMS's and GMS's internal administrative APIs over HTTP for role-permission, office, and live-status work. That route is the correct boundary pattern.

## Classification before change

| Category | Inventory |
| --- | --- |
| Reuse as-is | DMS and GMS root split; their `/api/v1` route organization; DMS OIDC/JWKS validation; DMS back-channel logout receiver; DMS/GMS health, validation, security middleware, queues, and OpenAPI tooling. |
| Move | SSO browser-facing templates and static client concerns out of the IdP runtime into `SSO/frontend/`; retain the identity and OIDC implementation in `SSO/backend/`. |
| Rename / reconfigure | Local ports, frontend public API URLs, OIDC redirect/logout URLs, SSO issuer, and documented service URLs to the 7100/7101, 7200/7201, and 7300/7301 allocation. |
| Rewrite / introduce | An HTTP-only SSO administration API suitable for DMS/GMS thin admin clients; client-scoped role assignment persistence in SSO; an event-based invalidation path for urgent deactivation/role changes. These require an incremental compatibility migration, not a direct database copy. |

## Baseline verification

No listening process was present on the old or target platform ports at discovery time. After the GMS port migration, a temporary real development process answered `GET http://127.0.0.1:7200/api/v1/health` with `200` and the expected success envelope, including a generated request ID. DMS and SSO have not yet been started on their target ports, so this brief does not claim end-to-end platform validation.

## Migration safety constraints

The parent SSO repository already contains a large, pre-existing uncommitted relocation from `IdP/` to `SSO/backend/`. DMS and GMS also contain unrelated working-tree changes. Platform work must preserve those changes and avoid broad moves, cleanup, resets, or lockfile rewrites.
