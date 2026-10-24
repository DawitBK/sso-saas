# SSO: the Example Corp identity provider

One sign-in for every system on the platform. SSO is the OpenID Connect identity provider, the admin console and the app-launcher portal, served at `portal.examplecorp.com/sso`.

| Part | Where | Port |
|---|---|---|
| Backend: OIDC provider, admin API, portal API, the GMS gateway | [`backend/`](backend/README.md) (Express 5 + `oidc-provider`, PostgreSQL `idpprod`) | 7300 (gateway 4200) |
| Frontend: sign-in pages, portal, admin console | `frontend/` (Next.js 16) | 7301 |

How it connects to the other systems: DMS is a standard OIDC client (`edams`); GMS signs in through a token bridge. Details in [SSO-ARCHITECTURE.md](docs/sso/SSO-ARCHITECTURE.md) (the two integration patterns) and [SSO-INTEGRATION-GUIDE.md](docs/sso/SSO-INTEGRATION-GUIDE.md).

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
