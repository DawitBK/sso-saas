# Example Corp SSO

Central identity provider (`oidc-provider`), admin console, and app
launcher portal for the Example Corp platform.

- `backend/` -- Express + `oidc-provider`, port 7300 (+4200 for the GMS
  bridge gateway relay, see `backend/src/gateway/server.ts`)
- `frontend/` -- Next.js, port 7301

## Local development

```bash
cd backend && npm ci && cp .env.example .env && npm run db:migrate && npm run db:seed:dev && npm run dev
cd frontend && npm ci && npm run dev
```

## Docker

```bash
docker compose -f docker-compose.dev.yml up -d   # postgres only
# then run backend/frontend locally as above, or:
docker compose --env-file backend/.env.production up -d --build   # full stack
```
