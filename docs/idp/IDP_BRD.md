# IDP_BRD — Business Requirements Document

**System:** Standalone Identity Provider (IdP) for EDAMS
**As of:** 2026-07-02
**Scope:** Custom Node/TS OIDC provider (reusing EDAMS auth code), OIDC/OAuth2 only in Phase 1, single tenant-scoped instance.

---

## 1. Purpose & Background

EDAMS currently embeds all authentication and identity logic *inside* the `backend/` monolith: RS256 JWT issuance, two-phase tenant selection, RBAC (40 permissions across 6 roles), tenant-scoped permission overrides, MFA/TOTP, OIDC-client support, a dev JWKS endpoint, and a hash-chained audit log. This works for a single application but does not scale to an organization that will run **multiple** applications (web portals, mobile apps, internal tools) against the same user base.

This document defines the business need for a **standalone Identity Provider (IdP)** — an independently deployed service that centralizes authentication and identity so that EDAMS and future applications share one login, one credential store, one MFA policy, and one audit trail.

## 2. Business Objectives

| # | Objective |
|---|---|
| BO-1 | **Single Sign-On (SSO)** across EDAMS and future Example Corp applications. |
| BO-2 | **Centralized user lifecycle** — provision, deactivate, and audit users in one place. |
| BO-3 | **Centralized security policy** — MFA enforcement, password rules, account lockout, key rotation managed once. |
| BO-4 | **Reduced duplication & risk** — applications stop storing credentials or reimplementing login. |
| BO-5 | **Standards-based interoperability** — OIDC/OAuth2 so any compliant app can integrate by configuration. |
| BO-6 | **Auditability & compliance** — immutable, centralized authentication audit. |

## 3. Stakeholders

| Stakeholder | Interest |
|---|---|
| Example Corp IT / Security | Central control of identity, MFA, key rotation, audit. |
| EDAMS product team | Remove auth burden from the app; consume identity via standard tokens. |
| Tenant administrators | Manage their users and tenant memberships. |
| End users | One credential and one MFA enrolment across all apps. |
| Future application teams | Onboard via OIDC configuration, not custom code. |

## 4. Scope

**In scope (Phase 1)**
- OIDC/OAuth2 Identity Provider: authorization-code + PKCE, refresh tokens, discovery, JWKS, token introspection & revocation, RP-initiated logout.
- Single IdP instance, **tenant-scoped** (tenants as slug namespaces, preserving login → select-tenant → scoped-token UX).
- Authentication features: password login, MFA/TOTP, account lockout, forced password change.
- Identity data: users, tenant membership, coarse roles/groups.
- EDAMS onboarded as the first OIDC client (Relying Party).
- Administration API for users, tenants, memberships, roles/groups, and client registration.

**Out of scope (Phase 1, deferred)**
- SAML 2.0 IdP.
- External/upstream federation (Google, Microsoft Entra/Azure AD, LDAP).
- Self-service public registration.
- Fine-grained application permissions (these remain in each consuming app).

## 5. Business Requirements

| # | Requirement |
|---|---|
| BR-1 | Users authenticate once and access multiple applications without re-entering credentials. |
| BR-2 | The IdP is the authoritative store of user credentials and identity; consuming apps hold no passwords. |
| BR-3 | MFA can be enforced per user (and, later, per tenant/policy). |
| BR-4 | Multi-tenant users select a tenant; the issued token is scoped to that tenant. |
| BR-5 | All authentication events are recorded in an immutable, centralized audit log. |
| BR-6 | Signing keys can be rotated without downtime; consumers auto-discover keys via JWKS. |
| BR-7 | A new application can be onboarded through configuration/registration only — no IdP code changes. |
| BR-8 | The service is deployed and operated **independently** of EDAMS (own DB, own lifecycle). |

## 6. Success Metrics

- EDAMS authenticates end-to-end through the IdP with **zero** credentials stored in EDAMS.
- Users manage **one** credential + MFA enrolment across applications.
- Onboarding a new client app requires only client registration + config (no code).
- 100% of authentication events appear in the centralized audit log.

## 7. Assumptions, Constraints, Risks

**Assumptions** — EDAMS's existing OIDC-client capability (`AUTH_ISSUER`, `AUTH_JWKS_URI`, `/auth/callback`, `idp_role_mappings`) is reused; Node/TS/Postgres/Redis remain the platform standard.

**Constraints** — Must preserve current tenant-scoped UX; must run alongside EDAMS during a migration window; secrets and keys must not be committed.

**Risks & mitigations**

| Risk | Mitigation |
|---|---|
| Migration downtime / user disruption | Dual-run window with EDAMS local login behind a flag; documented rollback. |
| Token/claim mismatch breaks EDAMS authorization | Keep IdP token claims aligned to EDAMS's expected shape (`tenant_id`, roles/groups). |
| Key compromise | Rotation schedule; secrets in a secret store, not the repo. |
| Single point of failure | Stateless service + HA deployment; Redis/DB backups. |

## 8. Glossary

**IdP** — Identity Provider. **RP / Client** — Relying Party (an app that authenticates via the IdP, e.g., EDAMS). **Tenant / realm** — a slug-scoped organizational namespace. **Claim** — an assertion in a token (e.g., `email`, `tenant_id`). **JWKS** — JSON Web Key Set (public keys for token verification). **PKCE** — Proof Key for Code Exchange.

---

*Related: [IDP_FRD.md](IDP_FRD.md), [IDP_TDD.md](IDP_TDD.md), [IDP_IMPLEMENTATION_PLAN.md](IDP_IMPLEMENTATION_PLAN.md)*
