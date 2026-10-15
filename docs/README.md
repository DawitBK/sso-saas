# SSO documents

## `sso/`: current guides for this system

| Document | What it answers | Page |
|---|---|---|
| [SSO-OPERATIONS.md](sso/SSO-OPERATIONS.md) | Run, configure, rotate keys, manage sessions, check the audit chain, back up, troubleshoot | [page](sso/SSO-OPERATIONS.html) |
| [SSO-ARCHITECTURE.md](sso/SSO-ARCHITECTURE.md) | The design, and why SSO is not a gateway or shell | [page](sso/SSO-ARCHITECTURE.html) |
| [SSO-INTEGRATION-GUIDE.md](sso/SSO-INTEGRATION-GUIDE.md) | How to connect a new system | [page](sso/SSO-INTEGRATION-GUIDE.html) |
| [SSO-INTEGRATION-CODE-REFERENCE.md](sso/SSO-INTEGRATION-CODE-REFERENCE.md) | The exact env values and working code for an integration | [page](sso/SSO-INTEGRATION-CODE-REFERENCE.html) |
| [SSO-AUDIT.md](sso/SSO-AUDIT.md) | The latest full audit of SSO | — |
| [SSO-COMPLETION-REGISTER.md](sso/SSO-COMPLETION-REGISTER.md) | What the 2026-10-11 completion pass changed, how it was verified, and the open items | — |

## `platform/`: platform-wide decisions and history

Kept here because SSO is the root repo. GMS and DMS link to these by path, so **don't move them**.

| Document | What it is |
|---|---|
| [PLATFORM_ARCHITECTURE.md](platform/PLATFORM_ARCHITECTURE.md) | How the systems fit together |
| [ADR.md](platform/ADR.md) | Platform architecture decisions |
| [DEFECT_AND_GAP_REGISTER.md](platform/DEFECT_AND_GAP_REGISTER.md) | The platform gap register (pull-request templates point here) |

## `idp/`: the original requirements and design (July 2026)

[IDP_BRD.md](idp/IDP_BRD.md) · [IDP_FRD.md](idp/IDP_FRD.md) · [IDP_TDD.md](idp/IDP_TDD.md). Closed references, not a worklist; `backend/src/config.ts` cites the TDD.

## Elsewhere

- [`../backend/README.md`](../backend/README.md): routes, clients, scripts.
- `../backend/docs/TEST_STATUS.md`: **generated** by `npm run test:status`; CI fails if it is out of date. Don't edit or move it.
- `../backend/docs/API.md`: an older description of the JSON API for the frontend; check against the code.

[← SSO](../README.md) · [Platform start page](../../README.md)
