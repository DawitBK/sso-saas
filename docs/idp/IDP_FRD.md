# IDP_FRD — Functional Requirements Document

**System:** Standalone Identity Provider (IdP) for EDAMS
**As of:** 2026-07-02

---

## 1. Actors

| Actor | Description |
|---|---|
| End user | Authenticates to access applications. |
| Tenant admin | Manages users/memberships within a tenant. |
| IdP super-admin | Manages tenants, global roles, and client (RP) registrations. |
| Client application (RP) | Requests authentication via OIDC (e.g., EDAMS). |

## 2. Responsibility Boundary (IdP vs consuming app)

| Concern | Owner |
|---|---|
| Credentials, password hashing, login, MFA/TOTP, lockout | **IdP** |
| Identity (`sub`, email, name), tenant membership, coarse roles/groups | **IdP** |
| Sessions, refresh tokens, revocation, key/JWKS rotation, SSO | **IdP** |
| OIDC/OAuth2 endpoints, discovery, consent | **IdP** |
| Mapping roles/groups → app permissions, ACLs, domain logic | **Consuming app (EDAMS)** |

## 3. Functional Requirements

### 3.1 Authentication

| # | Requirement | Acceptance criteria |
|---|---|---|
| FR-1 | Password login | Valid email+password authenticates; invalid credentials are rejected with a generic error. |
| FR-2 | Account lockout | After N failed attempts, account is locked until `lockedUntil`; further attempts rejected. |
| FR-3 | Forced password change | Users flagged `mustChangePassword` must set a new password before receiving tokens. |
| FR-4 | MFA/TOTP enrolment | User can set up TOTP (secret + otpauth URI) and confirm with a valid code. |
| FR-5 | MFA challenge | When MFA is enabled, a valid TOTP code is required to complete login. |
| FR-6 | MFA disable | Disabling MFA requires a valid current TOTP code. |

### 3.2 Tenant Selection

| # | Requirement | Acceptance criteria |
|---|---|---|
| FR-7 | Multi-tenant selection | Users with >1 tenant membership are prompted to choose; token is scoped to the chosen tenant. |
| FR-8 | Single-tenant auto-select | Users with exactly one membership skip selection. |
| FR-9 | Tenant switch | An authenticated user can switch tenants, receiving a newly scoped token. |

### 3.3 OIDC / OAuth2 Endpoints

| # | Requirement |
|---|---|
| FR-10 | Discovery — `GET /.well-known/openid-configuration`. |
| FR-11 | JWKS — `GET /jwks.json`. |
| FR-12 | Authorization — `GET /authorize` (authorization code + **PKCE required**). |
| FR-13 | Token — `POST /token` (code exchange, refresh with rotation). |
| FR-14 | UserInfo — `GET /userinfo`. |
| FR-15 | Introspection — `POST /introspect`. |
| FR-16 | Revocation — `POST /revoke`. |
| FR-17 | RP-initiated logout / end session. |

### 3.4 Claims Contract

| # | Requirement |
|---|---|
| FR-18 | ID/access tokens include `sub`, `email`, `email_verified`, `name`, and (post tenant-selection) `tenant_id`, `roles[]`, `groups[]`. Shape aligned to EDAMS's expectations so its permission mapping and ACL resolution continue to work. |

### 3.5 Administration

| # | Requirement |
|---|---|
| FR-19 | Manage users (create, update, activate/deactivate). |
| FR-20 | Manage tenants and user-tenant memberships. |
| FR-21 | Manage roles/groups and their assignments. |
| FR-22 | Register/manage OIDC clients (redirect URIs, grant types, scopes, secret). |
| FR-23 | View the authentication audit log. |

## 4. Primary User Flow (login)

```
RP (EDAMS) → GET /authorize (code + PKCE, state, nonce)
  → IdP: Login (FR-1/2/3)
  → IdP: MFA challenge if enabled (FR-5)
  → IdP: Select tenant if multi-tenant (FR-7) else auto (FR-8)
  → IdP: Consent (auto for trusted first-party clients)
  → redirect back to RP with authorization code
RP → POST /token (code + PKCE verifier) → ID + access + refresh tokens
RP → verifies token via JWKS; reads tenant_id, roles, groups
```

## 5. Non-Functional Requirements

| # | Requirement |
|---|---|
| NFR-1 | **Security** — OWASP ASVS alignment; PKCE mandatory; state/nonce replay protection; refresh-token rotation; token revocation. |
| NFR-2 | **Availability** — stateless service, horizontally scalable; HA deployment target. |
| NFR-3 | **Performance** — token issuance within an acceptable latency budget under expected load (set during load testing). |
| NFR-4 | **Auditability** — immutable, hash-chained audit for all auth events. |
| NFR-5 | **Operability** — health/readiness endpoints; structured logs; migrations run on deploy. |
| NFR-6 | **Portability** — Dockerized; same platform conventions as EDAMS. |

---

*Related: [IDP_BRD.md](IDP_BRD.md), [IDP_TDD.md](IDP_TDD.md), [IDP_IMPLEMENTATION_PLAN.md](IDP_IMPLEMENTATION_PLAN.md)*
