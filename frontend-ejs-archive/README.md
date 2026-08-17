# SSO Frontend

This directory is the **browser entry point** for SSO on port **7301**.

- `src/server.ts` runs an independent Express process that:
  - Renders EJS templates for UI routes (`/portal`, `/admin`, `/interaction`,
    `/bridge`) from JSON view models returned by the backend (`X-SSO-UI: 1`).
  - Reverse-proxies OIDC protocol, `/api/v1`, health, and JWKS traffic to the
    backend at `http://localhost:7300` over HTTP.
- `src/views/` holds the EJS templates. The frontend owns rendering; the backend
  still keeps a compatibility render path for direct `:7300` access without the
  UI header.

## Run (dev)

Start the backend first, then the frontend:

```bash
cd SSO/backend
npm run dev          # http://localhost:7300 (API/OIDC runtime)

cd SSO/frontend
npm install
npm run dev          # http://localhost:7301 (browser UI + proxy)
```

Set `IDP_ISSUER=http://localhost:7301` and `IDP_INTERNAL_URL=http://localhost:7300`
in `SSO/backend/.env` so OIDC discovery, redirects, and token `iss` claims match
the browser-facing URL while server-side token/JWKS calls stay on the backend port.

## Verification

With both processes running:

```bash
cd SSO/backend
node test-scripts/live-login.mjs
node test-scripts/assert-view-model-split.mjs
node test-scripts/admin-internal-clickthrough.mjs
```

The scripts default to `http://localhost:7301`.
