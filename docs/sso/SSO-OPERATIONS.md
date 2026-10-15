# Example Corp SSO — Operations

Running the identity provider day to day: what to check, what the admin
console's sensitive actions actually do, and how to recover. Design is
covered in `SSO-ARCHITECTURE.md`; onboarding a new relying party is
`SSO-INTEGRATION-GUIDE.md`; a full platform deploy has its own dedicated
runbook.

## Contents

1. [Service basics](#1-service-basics)
2. [Running it](#2-running-it)
3. [Configuration](#3-configuration)
4. [Signing keys](#4-signing-keys)
5. [Sessions and the audit chain](#5-sessions-and-the-audit-chain)
6. [Backups](#6-backups)
7. [Troubleshooting](#7-troubleshooting)

---

## 1. Service basics

Every relying party's development port is also its production port; only
the environment name, host binding, database name/password, and public
URL differ between the two. All databases can live on one shared
database instance, but no two systems ever share a database.

**The browser entry point is the frontend port, not the backend port.**
The backend serves JSON view models, not rendered pages — opening the
backend port directly gets you JSON, not the login screen.

**Redis (or an equivalent shared cache) is optional.** Without it
configured, rate limiters fall back to a per-process in-memory store,
which is correct for a single instance. Configure a shared cache only
once the identity provider runs more than one process — otherwise the
effective rate limit is silently divided by the instance count, since
each process is enforcing its own separate counter.

**A no-touch legacy app reached through the gateway pattern** should be
addressed through a hostname that isn't a raw loopback IP in development
— a browser treats a raw loop-back address and a hostname that resolves
to it as different origins for cookie purposes, and getting this wrong
produces a session that silently never seeds. That app's own native login
paths (staff or guest) stay directly reachable on its own port,
completely unaffected by the gateway.

---

## 2. Running it

### Development

```bash
cd backend
npm install
cp .env.example .env       # then fill in secrets
npm run db:migrate         # apply migrations to the development database
npm run db:seed:dev        # seeds a starter admin account — see the script for the generated credentials
npm run dev                # starts the backend, and the gateway alongside it

cd ../frontend
npm install
npm run dev                # open this — the frontend, not the backend port
```

Migrations apply automatically on `npm run dev`. Production deliberately
does not do this — see below.

### Production

```bash
cd backend
npm run env:verify:prod    # resolves config, runs every production assertion, starts nothing
npm run build
npm run db:migrate:prod
npm run start:prod

cd ../frontend
npm run build              # the public base path must be set at BUILD time, not at runtime
npm start
```

`env:verify:prod` is the step worth never skipping before trusting a
deployed instance. It loads the real configuration module — so every
production assertion actually runs — and prints the resolved database,
issuer, directory-service settings, and registered clients, without
binding a port or touching the database. It never prints a secret value:
sensitive settings show as set/unset with a length only. Exit code `0`
means it's safe to start.

A process manager (PM2 or similar) and a container runtime are both
optional — nothing about running the identity provider requires either.

---

## 3. Configuration

**Production reads exactly one environment file and nothing else.** The
development environment file is never read in production; a missing
production environment file is a hard refusal to start, not a silent
fallback. Don't reintroduce a "layered" approach where a production file
is loaded on top of a development one — most `.env` loaders only override
the keys the layering file actually names, so any key the production file
doesn't mention silently keeps its development value.

**This matters more for the identity provider than for any relying
party**, because a misconfigured identity provider that boots
successfully — happily, against the wrong database, with a
development-looking issuer baked into every token it signs — hands out
tokens nothing downstream will recognize as wrong until users start
failing to log in elsewhere. Prefer a configuration loader that fails
loudly and specifically on a missing or placeholder-looking
production-required setting, rather than falling back to a safe-looking
default.

| Variable | Meaning |
|---|---|
| `IDP_ISSUER` | The canonical public URL — the `iss` claim baked into every token. Development typically points at localhost; production must be the real HTTPS origin. |
| `DATABASE_URL` | The identity provider's own database. The loader should refuse to boot on an ambient value the environment file itself did not define — see [§7](#7-troubleshooting). |
| `COOKIE_KEYS` | Session-cookie signing keys, comma-separated. Rotate by prepending a new key and leaving the old one in place until every live session has re-signed. |
| `TOTP_ENCRYPTION_KEY` | Encrypts stored MFA secrets at rest. **Changing it locks every enrolled user out of MFA** — see [§6](#6-backups). |
| `AUDIT_HMAC_KEY` | Keys the admin audit hash chain. |
| Directory-service variables (e.g. `LDAP_*`) | Enable directory-backed authentication. Leave empty for a local-user-store-only deployment. |
| Per-relying-party client secrets | One per registered OIDC client. Production should refuse to start on any development-default secret value. |
| A relying party's own runtime secret (e.g. a bridged app's JWT signing secret) | **Must exactly match** that app's own configured secret, or every bridged token is rejected on that app's side. |
| A relying party's internal API base URL and key | Used by the identity provider to call into that app's own internal API — for example, to mint a bridged session or manage role assignments. |
| A shared cache URL (e.g. `REDIS_URL`) | Optional. Backs a shared rate-limit store across more than one process. |
| `ENABLE_API_DOCS` | Whether to expose interactive API documentation in production. Off by default — turn on deliberately, not as a leftover from debugging. |

---

## 4. Signing keys

Signing keys are stored in the identity provider's own database. Exactly
one is active at a time — that's the key used to sign new tokens. The
JWKS endpoint publishes the active key **plus** any key retired within an
overlap window (roughly the longest token lifetime the provider issues,
plus a safety margin), so a token signed moments before a rotation still
verifies for its natural lifetime.

Both operations below should take effect **live**, with no restart
required — an identity provider is exactly the kind of shared dependency
where a restart-to-rotate cost is unacceptable.

**Rotate** (the routine, scheduled operation): generates a new key, makes
it active, and marks the previous one retired. The retired key stays
published for the overlap window. This costs nobody a login.

**Withdraw immediately** (the emergency operation): removes a key from
the JWKS right away, ahead of its normal overlap window. **Every token
still signed with that key stops verifying at once, and every affected
user must sign in again.** That's the point — this is the action for a
key believed compromised, not for routine housekeeping. Rotate first;
withdraw only the key you've already rotated away from, unless you
specifically believe the *active* key itself is compromised.

Verify what relying parties can actually see at any time by fetching the
provider's own JWKS and discovery document directly.

---

## 5. Sessions and the audit chain

**Sessions.** An admin console should let an operator list live sessions
and revoke one — revoking should act on the live session store directly,
which has a real consequence for point-in-time restores (see
[§6](#6-backups): a restored database reintroduces whatever sessions were
live at backup time). A per-user "sign out everywhere" action is a useful
minimum for an admin console to expose.

Give users the same self-service capability for their own account:
enrolling MFA, listing and individually revoking their own sessions,
reviewing their own sign-in history, and changing their own password if
their account isn't sourced from a directory service.

**Audit chain.** Keep the admin audit log hash-chained: each row's hash
covers the previous row's, so an edit or deletion anywhere breaks
verification from that point on. Run the verification check periodically,
both as a script and as a live admin-console action. **A broken chain
means rows were altered outside the application — treat that as a
security incident, not a data-quality problem.**

**Retention.** A background job should periodically purge expired OIDC
artifacts and stale sessions, and a separate job should re-sync directory
group membership for users with a live session on some regular interval,
so a group-membership change takes effect within that interval rather
than waiting for the session to naturally expire.

---

## 6. Backups

Every production identity-provider deployment needs a scheduled database
backup with a defined retention period, and — just as important — a
tested restore procedure, not just a backup file assumed to be good.
Offset the backup schedule from other systems' backup jobs on the same
host so multiple database dumps aren't competing for the same disk at the
same moment.

**Treat any backup or restore script as security-relevant code.** A
backup script that silently fails — throws on an unrelated bug before
doing any real work, or gets pointed at the wrong database by an
environment-loading mistake — can report success while producing nothing
useful, for a long time, before anyone notices. After any change to
backup tooling, verify a real, restorable file actually lands; never
trust an exit code alone.

**The identity provider's own database deserves the platform's most
conservative backup posture.** Losing any one relying party's data loses
that system; losing the identity provider's database severs every
integrated system's authentication path simultaneously.

Keep any encryption or signing keys used for stored secrets (an
MFA-secret encryption key, an audit-chain signing key) somewhere durable
and **separate from the backup itself**. A restored database without the
original key that encrypted a given column means that data is
permanently unrecoverable from the dump alone, no matter how recent or
complete it is — a lost MFA-secret encryption key, specifically, means
every enrolled user must re-enroll their authenticator from scratch.

---

## 7. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| The identity provider connects to a database you didn't configure | A machine-wide `DATABASE_URL` left over from an unrelated project or trial deployment is silently winning over the service's own environment file. The configuration loader should refuse to boot on an ambient value the environment file did not itself define — check the machine's actual environment variables. |
| Everything works, but tokens carry a development-looking issuer | The service started outside production mode and loaded the development environment file. Run the production config-verification script and check which file it reports reading. |
| A bridged relying party rejects a freshly issued token | That app's configured runtime secret doesn't match what the identity provider is signing with. |
| A relying party's callback fails on first login | Its own cache/queue dependency (Redis, for instance) may be down and its nonce check is fail-closed, or its own group-to-role mapping table has no row for that user's group. |
| Every user's MFA suddenly fails | The MFA-secret encryption key doesn't match the key the secrets were originally encrypted with. Restore the previous key rather than letting users burn through lockout attempts — MFA lockout is real and will lock accounts out further. |
| A relying party rejects freshly issued tokens across the board | A signing key was withdrawn rather than rotated, or that relying party has cached the JWKS response longer than it should. Check which keys are currently published. |
| A public/guest flow can't reach an app | It should be using that app's own native public flow — a guest or public flow is a business flow specific to that app, not an identity-provider flow, and should never be routed through the bridge. |
| A path under the portal's own base path 404s in production | The frontend was built without its production base path set. It's baked in at build time — rebuild, don't just restart. |
| The plain framework "start" command serves nothing | The frontend is a standalone-output build and can't be served that way — use the project's own start script, which runs the standalone launcher. |


---

## 13. 2026-10-11: supervision, health, settings, applications, recovery codes, notification retry

**Supervision.** SSO exits on any unhandled fatal error on purpose (an identity provider running from an unknown state is worse than one
that restarts clean), so something has to bring it back. `deploy/supervise.cjs` does: it restarts the process whenever it exits (1 s, 2 s,
4 s ... 30 s back-off, reset after a minute of health), and kills and restarts one that is up but no longer answering `/health` (four failed
probes, 15 s apart, after a 60 s grace). One supervisor per name (a lock file with a heartbeat), so re-running `production-start.bat` cannot
start a second copy. Start: `npm run start:prod:supervised` (backend) and `npm run start:supervised` (frontend); the mirror uses
`start:mirror:supervised`. Stop: `npm run stop:supervised` in each folder (killing only the node child just makes it come back). Its log
and state are `logs/supervisor-<name>.log` and `.json` (restarts, last exit). `production-start.bat` and `start-mirror-all.ps1` already use it.
`npm run test:supervisor` proves it against real child processes.

**Health.** `/health` is liveness. `/health/ready` (and `/api/v1/health/ready`) answers 503 only when the database or the active signing key is
unusable; everything around SSO (Redis, DMS, GMS, a pending migration, the DMS role lookup, stuck sign-out notifications, an event loop that
stalls) makes it *degraded*, still 200, so a monitor keeps sending traffic. An anonymous caller sees state words only. Admin > System
health shows the reasons, DMS/GMS reachability, jobs, password-check load and whether this process is supervised.

**Settings.** Admin > Settings. Defaults come from the environment; a stored value wins and applies at once (token lifetimes are read by
oidc-provider for every new token). Only the platform administrator may change password rules, lockout, two-factor for administrators,
token and session lifetimes and retention; any console administrator may change branding and the portal message and hide an application's
tile. Every change is validated, audited with the old and new value, and can be reset. If the table cannot be read SSO keeps the last
values it had (or the defaults) and signs people in regardless.

**Applications.** Admin > Applications (platform administrator for changes). Edits to a client's addresses, switching it off, and rotating its
secret take effect on the next request. After rotating the DMS client's secret put the new value in `DMS/backend/.env.production`
(`OIDC_CLIENT_SECRET`) and restart DMS; GMS needs nothing (the bridge inside SSO reads the database). The `portal` client is protected.

**Two-factor recovery codes.** Ten single-use codes shown once when two-factor is switched on, replaceable with a current authenticator
code. A person who lost their phone uses one at the two-factor step ("Lost your phone?"). The codes are stored as an HMAC keyed from
`TOTP_ENCRYPTION_KEY`, so **changing that key invalidates every recovery code and every authenticator secret**. An administrator's reset
clears two-factor and the codes.

**Sign-out notices to DMS and GMS.** A failed "end this person's sessions" call is queued (`idp_pending_notifications`) and retried by a
background job for 48 hours (1 min, 2, 5, 15, 30, 60 min, 2 h, then every 4 h). The System page and the health check show what is stuck;
after 48 hours it is abandoned and reported, and the session must be ended in that system by hand.

**Sign-in load.** Password checks are bounded (`PASSWORD_HASH_CONCURRENCY`, `PASSWORD_HASH_QUEUE`, `PASSWORD_HASH_WAIT_MS`); past the bound a
sign-in gets a 503 "busy, try again" instead of everything slowing down, and is not counted as a failed password. The supervised start
scripts set `UV_THREADPOOL_SIZE=8`.

**Frontend headers.** `proxy.ts` sends a nonce-based Content-Security-Policy, `X-Frame-Options: DENY`, nosniff, a referrer policy and a
permissions policy on every page. `SSO_CSP=report-only` or `off` (frontend environment, read at run time) is the break-glass if a policy
ever blocks something it should not. The Apache vhost still adds its own headers (its `X-Frame-Options` is SAMEORIGIN and replaces ours;
the CSP `frame-ancestors 'none'` still forbids framing).

**Supply chain.** CI runs `node scripts/audit-gate.mjs`: any high or critical advisory in the shipped dependencies fails the build unless it
is listed in that file with a reason and an expiry date. One entry today: `braces` (no fixed version exists; reached only through
`http-proxy-middleware` with fixed paths), expires 2027-01-31.


---

## 14. 2026-10-11 (second pass): audit chain, metrics, password reset requests, more than one process

**The old console is gone.** The server-rendered `/admin` pages on the backend's own port were removed. The Next.js console (`/sso/admin`) is the only console; it calls
`/api/v1/admin/*`. A bookmark to the backend port's `/admin` never worked through Apache and now answers 404.

**Audit chain.** `GET /api/v1/admin/audit/verify` (the Audit page's "Verify integrity") now lists every break, with who explained it. A background job verifies the chain
every six hours and shortly after start; while any break is unexplained the System page shows "Audit log integrity: Needs attention", `/health/ready` reports the
`auditChain` check as degraded (still HTTP 200), `sso_audit_chain_valid` is 0 and the log carries an `[idp:audit] ALERT` line.
What to do when it is red: open Admin > Audit log > Verify integrity, read each problem, and decide.
- *An entry was edited / missing / reordered / the start deleted* (`hash`, `linkage`, `ordering`, `head`): find out why. If it is old and explained (a restore from an older backup, a
  hand repair) the **platform administrator** acknowledges it with a reason of at least 20 characters. The problem stays listed, marked acknowledged; the acknowledgement becomes an entry in
  the chain; if that entry is altered again it is a new open problem. Nobody else can acknowledge.
- *The end deleted or the last entry edited / the whole log deleted* (`tail`, `empty`): recent entries are missing. This cannot be acknowledged. Restore the database from the last good backup
  (`BACKUP-RESTORE-MANUAL-PROD.md`) and look for how it happened.
`npm run audit:verify` prints the same list from a terminal. Dev only: `npm run db:ack:dev-audit` acknowledges the ten July 2026 entries in the dev database.

**Metrics for Prometheus.** `GET /metrics?format=prometheus` on the backend's own port (7300; Apache does not route it). Set `METRICS_API_KEY` in `.env.production` and send it as
`x-metrics-key`. Alert on: `sso_readiness_status{status="not_ready"} == 1`, `sso_audit_chain_valid == 0`, `sso_peer_up == 0`, `sso_notifications_oldest_pending_seconds > 900`,
`increase(sso_password_checks_refused_total[5m]) > 0`, `time() - sso_job_last_success_timestamp_seconds{job="purge"} > 7200`, `sso_supervised == 0` in production, and
`increase(sso_supervisor_restarts_total[1h]) > 3`. The full list of series and a scrape config are in `backend/docs/API.md`.

**"Forgot your password?"** There is no mail server, so the sign-in page link sends the request to the administrators: Admin > Users shows "N people are waiting for a password reset"
with what each person typed; reset the password on their page (this closes the request) and tell them the temporary one in person or by phone. The public answer is the same for every address
and a request exists only for an active local account (Active Directory accounts are reset in the directory). Switch it off under Admin > Settings > Passwords. Five requests per address per
15 minutes (`RESET_REQUEST_RATE_LIMIT`). Requests are kept 90 days once handled, and an untouched one is dropped after 30 days. The temporary password you set must satisfy the platform password rules.

**Running more than one SSO process.** What is shared through the database already: sessions, tokens and grants, settings (re-read every 10 s), the notification retry (`SKIP LOCKED`), the audit chain
(an advisory lock serialises writers), and the purge and AD re-check sweeps (one process at a time, `runExclusive`). Signing keys follow the table (checked every 30 s), so a rotation made through
one process reaches the others, and a retired key stops being published when its overlap ends. What is per process: the password-check gate, the DMS-roles circuit breaker, the DMS/GMS reachability
probes, the job counters and the audit-chain verdict (each process shows its own on the System page), and **rate limits unless `REDIS_URL` is set**: without Redis, N processes allow N times the
limits. So a second process is safe behind a load balancer if both use the same database, the same `.env.production` secrets and `REDIS_URL`. The supported way to stay up is still one supervised
process (a restart takes seconds); a second process is for when that stops being enough.
