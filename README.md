# SSO: an OpenID Connect identity provider with an admin console and app launcher

A self-hosted identity provider (IdP) for a small platform of internal systems: one sign-in, one admin console, one place to decide who can open which app. Built on `oidc-provider` (Express 5, TypeScript) with a Next.js 16 frontend and PostgreSQL. This is the company-neutral edition (the company is "Example Corp").

## What it does

- **OpenID Connect provider.** Authorization-code flow with PKCE, signed ID tokens, JWKS, RP-initiated and back-channel sign-out, per-client scopes and client-scoped roles.
- **Admin console.** Users, groups, role mappings, per-user app access, client management, sign-in history and an audit log.
- **App launcher portal.** Each user sees only the apps they are entitled to open.
- **Two integration patterns.** A standard OIDC client (DMS), and a token bridge with a same-origin gateway for an app that has its own login (GMS) with no changes to that app.
- **Security.** TOTP two-factor with replay protection, rate-limited sign-in with optional password lockout, a hash-chained audit log you can verify (`npm run audit:verify`), and single-use owner verification for the most sensitive operations.
- **Platform licensing.** Signed licence tokens per system with expiry, grace, seat limits and an offline signing tool.
- **Operations.** A supervisor that restarts a crashed or hung process, numbered SQL migrations (with down scripts), backups and a CI workflow.

| Part | Where | Port |
|---|---|---|
| Backend: OIDC provider, admin API, portal API, the GMS gateway | [`backend/`](backend/README.md) (Express 5 + `oidc-provider`, PostgreSQL) | 7300 (gateway 4200) |
| Frontend: sign-in pages, portal, admin console | `frontend/` (Next.js 16, React 19) | 7301 |

## Quick start (development)

You need Node 22 and Docker (for PostgreSQL).

```bash
docker compose -f docker-compose.dev.yml up -d      # PostgreSQL on port 5436
cd backend
cp .env.example .env                                # then point DATABASE_URL at the container
npm install
npm run db:migrate
npm run db:seed:dev                                 # dev login: admin@examplecorp.com / demo
npm run dev                                         # http://localhost:7300
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev                                         # http://localhost:7301
```

Run the checks with `npm run typecheck` and `npm test` in `backend/`. The backend has 60+ test files covering sign-in, tokens, licensing, owner verification and the audit chain.

How it connects to the other systems: DMS is a standard OIDC client (`edams`); GMS signs in through a token bridge. Details in [SSO-ARCHITECTURE.md](docs/sso/SSO-ARCHITECTURE.md) and [SSO-INTEGRATION-GUIDE.md](docs/sso/SSO-INTEGRATION-GUIDE.md).

## I want to…

| I want to… | Open |
|---|---|
| **run, configure or troubleshoot** it | [SSO-OPERATIONS.md](docs/sso/SSO-OPERATIONS.md) |
| understand **the design** | [SSO-ARCHITECTURE.md](docs/sso/SSO-ARCHITECTURE.md) |
| **connect a new system** to SSO | [SSO-INTEGRATION-GUIDE.md](docs/sso/SSO-INTEGRATION-GUIDE.md), then [the exact env values and code](docs/sso/SSO-INTEGRATION-CODE-REFERENCE.md) |
| see **the routes, clients and scripts** | [backend/README.md](backend/README.md) |
| see **what the 2026-10-11 completion pass did and what is still open** | [SSO-COMPLETION-REGISTER.md](docs/sso/SSO-COMPLETION-REGISTER.md) |
| **deploy** it | [DEPLOY-WINDOWS-MANUAL.md](DEPLOY-WINDOWS-MANUAL.md) (plain Node on Windows); containers: [docker-compose.yml](docker-compose.yml) |
| see **how licensing works** | [PLATFORM-LICENSING.md](docs/operations/PLATFORM-LICENSING.md) |
| see **all SSO documents** | [README.md](docs/README.md) |

## Related repositories

[gms-saas](https://github.com/DawitBK/gms-saas) (visitor management), [dms-saas](https://github.com/DawitBK/dms-saas) (documents and records) and [saas-platform](https://github.com/DawitBK/saas-platform), which runs all of them together with Docker Compose.

## License

[MIT](LICENSE)