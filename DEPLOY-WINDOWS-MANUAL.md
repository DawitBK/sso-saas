# SSO — manual Windows deploy

**This page is the SSO deploy walkthrough for a plain Node process on Windows.**
DMS and GMS each have a same-named page in their own editions; all three sit
behind one shared Apache vhost (section 5).

Everything below assumes SSO is deployed as a plain Node process. Docker
(`backend/Dockerfile`) and PM2 (`deploy/ecosystem.config.cjs`) are both
optional and neither is running unless someone deliberately starts it.

> **What this page used to say, and why it was wrong.** Until 2026-09-06 it told
> you to put production values in `backend\.env` with `NODE_ENV=production`
> in it, to run `npm run db:migrate` and `npm run start`, and to create a
> database called `idp`. Every one of those is now incorrect: production reads
> `.env.production` and *nothing* else, the unsuffixed scripts operate on the
> **development** database, and the production database is `idpprod`. Following
> the old page would have migrated and served the dev database while looking
> like a successful production deploy.

## 1. Prerequisites

- Node.js 22.x
- PostgreSQL, with SSO's own `idpprod` database — separate from `dmsprod` and
  `gmsprod`, on the same instance.
- No Redis. SSO's rate limiters fall back to per-process in-memory stores, which
  is correct for a single instance. Set `REDIS_URL` only if SSO is ever scaled
  past one process.

## 2. Get the code onto the server

```powershell
git clone https://github.com/DawitBK/sso-saas C:\apps\sso
cd C:\apps\sso
```

Or copy the folder. Note the layout: **this whole top-level folder is the SSO
repository**. GMS and DMS are separate repositories (their own editions) and are
not part of this clone.

## 3. Configuration

Create **`backend\.env.production`** from `.env.production.example`, and
**`frontend\.env.production`** from its own example.

`.env.production` is gitignored because it holds real secrets, so it is never
part of a clone or a file copy — it has to be placed on the machine by hand.

Two rules that are easy to get wrong:

- **`.env` is the development file and is never read in production.** There is
  no layering. Anything production needs must be written into `.env.production`
  explicitly — it can no longer be inherited by accident.
- **A missing `.env.production` is a hard refusal to start**, not a silent
  fallback. That guard exists because every value in `backend/src/config.ts`
  has a development default: without it SSO would boot happily on the `idp` dev
  database with a localhost issuer baked into every token it signs, and nothing
  downstream would report a problem.

Then prove what it resolves to, before starting anything:

```powershell
cd C:\apps\sso\backend
npm run env:verify:prod
```

It loads the real config module (so every production assertion runs), prints the
resolved database, issuer, AD settings and registered clients, and exits 0 if it
is safe to start. It binds no port, touches no database, and prints no secret —
sensitive values show as set/unset with a length, so the output is safe to paste
into a deployment log.

If it reports the `idp` database instead of `idpprod`, stop: the wrong file is
being read.

## 4. Install, migrate, build, start

```powershell
cd C:\apps\sso\backend
npm ci
npm run build
npm run db:migrate:prod
npm run start:prod
```

```powershell
# separate console window
cd C:\apps\sso\frontend
npm ci
npm run build
npm start
```

Notes on the four things that differ from development:

- `npm run start:prod` goes through `scripts/run-with-env.cjs`, which sets
  `NODE_ENV=production` *before* the process starts. That ordering is what
  decides which env file gets loaded, and PowerShell has no portable inline
  `VAR=value command` syntax, hence the wrapper.
- `db:migrate:prod`, not `db:migrate`. The unsuffixed script targets `idp`.
- The frontend's `npm start` runs `scripts/start-standalone.cjs`, **not**
  `next start` — Next refuses to serve an `output: "standalone"` build through
  `next start`, and the standalone folder is missing `.next/static` and
  `public/` unless something copies them in. The launcher does both.
- `NEXT_PUBLIC_BASE_PATH=/sso` is consumed at **build** time. Changing it means
  rebuilding the frontend, not restarting it.

There is no worker process. SSO's only background activity is two in-process
`setInterval` jobs — an hourly purge of expired artifacts and a 30-minute AD
group re-sync — running inside the backend already started above.

Closing a console window stops that process. Add PM2, Task Scheduler or NSSM if
you want reboot survival; none of them is required.

## 5. Reverse proxy

The platform uses **path-based routing on one Apache vhost**, not a subdomain per
system: `portal.examplecorp.com/sso`, `/dms`, `/gms`. The exact vhost is
specific to the site and is not part of this repository: send `/sso` to the
frontend on `127.0.0.1:7301`, and add the narrow `/gms/__sso` rule the GMS bridge
gateway needs (to `127.0.0.1:4200`).

The backend binds `127.0.0.1:7300` only; the browser reaches SSO through the
frontend on 7301. TLS terminates at Apache and the app trusts `x-forwarded-*`.

## 6. Redeploy

```powershell
cd C:\apps\sso
git pull
cd backend;  npm ci; npm run build; npm run db:migrate:prod
cd ..\frontend;  npm ci; npm run build
```

Then restart both processes. Env files are not touched by a pull — they are
gitignored and live only on the server.

## 7. Backups

`idpprod` is the highest-impact database on the platform: losing any other
system's data loses that system, losing this one severs every system's
authentication path at once.

```powershell
cd C:\apps\sso\backend
npm run db:backup:prod                        # one-off
.\scripts\register-backup-task.ps1 -BackendPath C:\apps\sso\backend   # nightly Scheduled Task
```

The task runs at 02:40 by default, deliberately offset from DMS (02:00) and GMS (02:20) so three `pg_dump`
processes are not competing for the same disk. Ship the dumps off-server.

Keep `TOTP_ENCRYPTION_KEY` and `IDP_AUDIT_HMAC_SECRET` somewhere durable and
separate from the dumps. A restored database without the original
`TOTP_ENCRYPTION_KEY` leaves every enrolled user's MFA secret undecryptable, and
that is not recoverable from the dump.
