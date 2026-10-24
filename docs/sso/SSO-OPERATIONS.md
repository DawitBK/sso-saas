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
13. [2026-10-11: supervision, health, settings, applications, recovery codes, notification retry](#13-2026-10-11-supervision-health-settings-applications-recovery-codes-notification-retry)
14. [2026-10-11 (second pass): audit chain, metrics, password reset requests, more than one process](#14-2026-10-11-second-pass-audit-chain-metrics-password-reset-requests-more-than-one-process)
15. [2026-10-19: platform licensing](#15-2026-10-19-platform-licensing)
16. [2026-10-19: owner verification (a stolen session is not enough)](#16-2026-10-19-owner-verification-a-stolen-session-is-not-enough)

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
probes, 15 s apart, after a 60 s grace). One supervisor per name (a lock file with a heartbeat), so starting it again cannot
start a second copy. Start: `npm run start:prod:supervised` (backend) and `npm run start:supervised` (frontend); the mirror uses
`start:mirror:supervised`. Stop: `npm run stop:supervised` in each folder (killing only the node child just makes it come back). Its log
and state are `logs/supervisor-<name>.log` and `.json` (restarts, last exit). A server's start scripts should call these npm scripts.
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
secret take effect on the next request. After rotating the DMS client's secret put the new value in DMS's `.env.production`
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
  (section 6) and look for how it happened.
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

## 15. 2026-10-19: platform licensing

Contract: [PLATFORM-LICENSING.md](../operations/PLATFORM-LICENSING.md) (canonical; this section is the SSO half). One licence per system (`sso`, `gms`, `dms`), kept in SSO's `licenses` table (migration 025), managed by the
**platform administrator only** at Admin > Licences (the same line as the signing keys: a console administrator sees the page explain that and nothing else). A system with **no licence row is not restricted at
all**; migration 025 creates no rows, so deploying it changes nothing until someone saves a licence.

- **States:** active, expiring (the last `warn_days` before expiry), grace (`grace_days` after it, full function), expired (read-only). Perpetual = "Never expires". Computed by `src/licenses/state.ts`, which GMS and DMS copy.
- **Saving, extending, removing.** Save sets customer, expiry (a date means the end of that day, UTC), grace and warn days (0 to 365), seat limit, modules. **+30/+90/+365 days** counts from the later of the current expiry and now.
  **Remove** deletes the row (the system returns to "no licence"); the history stays in `license_events` and in the audit chain (`license.create|update|extend|revoke`). The licence version is the issue time (seconds since 2026-01-01 UTC; contract section 4.1), always higher than anything that system had before, even across a remove.
- **One version rule, every channel.** A system keeps the highest licence version it has seen and ignores a lower one, so the version is the **issue time**: the licence issued last wins, whether it was saved in this console, signed offline (`npm run license:sign`, which takes no version unless you pass `--version`) or issued by `license:dev-issue`. Nothing is tracked by hand. **Keep the issuing PC's clock correct**; to recover from a wrongly-set clock (a licence issued with the clock too far ahead), sign offline with an explicit `--version` higher than that one. The console shows the issue time, not the number (the number is in the tooltip). Old versions 1 to 6 are simply older than any new one, so the first licence issued under this rule replaces them. No migration was needed (INTEGER columns, good until 2094).
- **What GMS and DMS read:** `GET http://127.0.0.1:7300/api/v1/licenses/public/<gms|dms>` (mirror `:9300`): unauthenticated, 60 a minute per address, 404 when there is no licence. The answer is a signed token (RS256, the OIDC signing key,
  `typ kcms-license+jwt`, no `exp`; the claims are the contract's section 4). Rotating the signing key does not disturb a consumer that already holds a token.
- **SSO's own licence** is read from the database (cached 5 seconds, fails open) and shown by `GET /api/v1/licenses/status` (also `/api/v1/license/status`, any signed-in person) and the banner above every console page.
  When it is **expired** and `LICENSE_ENFORCEMENT=enforce`, `src/licenses/guard.ts` answers every POST/PUT/PATCH/DELETE with `403 LICENSE_EXPIRED` except the sign-in surface (interaction, `/authorize`, `/token`, `/me`, `/session`,
  `/device`, `/.well-known`, `/jwks`, the portal, the GMS bridge, `/api/v1/auth|portal|public`, health and metrics, the licence routes, `/api/v1/admin/csrf`, `/api/v1/internal` and `/internal`, and the signing-key actions
  `/api/v1/admin/keys`). So an expired SSO still lets everyone sign in to everything, and the platform administrator can still extend the licence.
- **Emergency switch:** `LICENSE_ENFORCEMENT=warn` in `.env.production` and restart SSO (`off` ignores licences entirely). `enforce` is the default. SSO logs a warning at boot when it is not `enforce`, or when the value is not one of the three words.
- **Where an operator looks:** Admin > Licences; the Audit page (filter `license.`); `SELECT * FROM license_events ORDER BY id DESC`.
- **Rolling back:** `migrations/025_licenses.down.sql` drops both tables (every system returns to "no licence"; the audit chain keeps its records).

## 16. 2026-10-19: owner verification (a stolen session is not enough)

Some operations are the owner's alone: signing keys, saving, extending or removing a licence, platform settings (password rules, lockout, two-factor, token lifetimes, log retention), an application's sign-in addresses, secret and on/off switch, who is an identity administrator, and acknowledging a break in the audit log. Being signed in as the owner used to be the only protection. Now each of them also needs a **one-time owner authorisation** that the server checks itself (never the browser alone). The list, with the plain-language warning shown for each, is `src/owner/registry.ts`; the same list is shown on Admin > Owner verification.

**What the owner does, each time.** Doing one of those actions opens a window that says what is about to happen and asks, in order: (1) the three security questions, (2) the code emailed to the owner's mailbox (or, when email cannot be used, one unused offline recovery code), (3) the six-digit code from the phone authenticator, **if this owner's enrolment has one** (see "The authenticator is optional" below; without it there are two steps and the window shows two). Then the action goes through once. The authorisation is for that one action on that one thing (for example "save the GMS licence"), for that browser sign-in only, and lapses after 5 minutes or after one successful use. If the action is refused for a reason that changed nothing (a mistyped date), the same authorisation can be used again until it lapses.

**Setting it up (first, before the first licence is saved on a server).** Do this on the SSO server, at a terminal, as the account that runs SSO:

1. In that environment's env file set `OWNER_STORE_KEY_FILE` to a path **outside the repository** (for example a folder only the SSO account can read) and, if the emailed code is wanted, the `SMTP_*` settings (`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`). `OWNER_VERIFICATION_REQUIRED` is true by default in production and the mirror, false in development; never set it to false on a live server (the release preflight refuses that).
2. Apply migration 027 (`npm run db:migrate:prod`), then run `node scripts/run-with-env.cjs production npx tsx scripts/owner-enroll.ts` (dev: `npm run owner:enroll`). You choose three questions and type the answers (hidden, twice), give the mailbox address (a test code is emailed to prove it), add the authenticator by typing the shown key (skipped when `OWNER_AUTHENTICATOR_REQUIRED=false`, and then it is "Step 3 of 3"), and are shown **ten recovery codes once**: write them on paper. Nothing is accepted from arguments, environment or pipes.
3. Restart SSO. `npm run owner:status` (production: `node scripts/run-with-env.cjs production npx tsx scripts/owner-status.ts`) shows what is set up with no secret in it.

Until the owner has enrolled, while verification is required, those operations are **refused** (`OWNER_NOT_ENROLLED`), never allowed. That includes saving a licence, so enrol before the licence step of a deployment. Signing in, health checks and the licence status endpoints keep working.

**If the emailed code stops working.** The emailed code is always sent through the mail relay (`SMTP_*`) configured in the environment that is running, so after you change `SMTP_*` in the env file and restart SSO the next code goes through the new relay (owner decision 2026-10-21; a difference from the relay at enrolment is only logged as a notice). Prove delivery from any environment with `npm run owner:test-mail` (production: `node scripts/run-with-env.cjs production npx tsx scripts/owner-test-mail.ts`). If SMTP is removed altogether or the mail server is unreachable, the emailed code becomes unavailable and **one unused recovery code takes its place**: the questions (and the authenticator, if this enrolment has one) are still required, so it is never fewer steps. A recovery code is not accepted while the emailed code works, and each one works once. After a deliberate change of mail server, run `owner:change-email` (it needs the vault password and a current authenticator code, or the three answers for an enrolment without the authenticator, and proves the mailbox by emailing it a code). When two or fewer recovery codes remain the page and `owner:status` say so: run `owner:recover` to make a new set.

**The authenticator is optional (owner decision 2026-10-21).** `OWNER_AUTHENTICATOR_REQUIRED=true|false` (default **false** since 2026-10-21, owner decision: the owner does not want the phone step; only the word `true` turns it on) decides what a **new** enrolment (`owner:enroll`, `owner:recover`) includes. With `false` the tool skips the authenticator step entirely (no secret is made or stored, the steps read "Step 1 of 3" to "Step 3 of 3" and the tool says plainly that this enrolment has no authenticator) and the owner proves themselves with two things: the security questions, then the emailed code (or one unused recovery code while email cannot be used). **The factors are fixed at enrolment**: the sealed owner store records `factors: { authenticator: true|false }`, and verification always demands the factors of the *stored* enrolment, never the current environment value. A store written before this field existed has none and means authenticator = true, and anything other than an explicit `false` in the store also means true. So flipping the setting never weakens an enrolled-with-authenticator owner, and never makes a without-authenticator owner start being asked for one; to change either way run `owner:recover` with the setting you want. For an enrolment without the authenticator the verification API refuses an authenticator code outright (`409 OWNER_AUTHENTICATOR_NOT_USED`, not counted as a wrong attempt, nothing stored), the dialog shows two steps, and every limiter, lockout and single-use rule applies unchanged to the factors that remain. The audit rows and the admin audit chain record which factors were used (`authenticator: used|not used`, never a secret). `owner:status` prints `authenticator: not used (enrolled without)` or `required (enrolled with it)`, and what a new enrolment would ask for.

**If something is lost.** Lost phone, forgotten answers, no recovery codes, or a lost key file: run `owner:recover`. It asks for the platform vault password (the one `platform-vault.ts set` chose) or one unused recovery code, then repeats the enrolment; the old questions, authenticator and recovery codes stop working at once. A missing key file is created again (vault password only). Too many wrong attempts lock the sequence (5 in a row: 5 minutes, then 15 minutes, 1 hour, 6 hours, 24 hours; a completed run resets it); nothing is checked while it is locked. `owner:unlock` clears a lock (vault password). Someone holding only a stolen session can lock the owner out by failing on purpose, never get in; the failures are raised as security events.

**Where it is recorded.** `owner_verification_audit` (every step and decision, no secret), the tamper-evident admin audit chain (ticket issued, operation authorised, lock) and security events (`owner_op_denied`, `owner_op_without_sequence`, `owner_verification_failed`, `owner_verification_locked`). No answer, code, address, secret or ticket is written anywhere. The first attempt of every owner-only action in the console is made without an authorisation and raises `owner_op_without_sequence` at `info`: that is the normal start, not an alarm.

**Honest limits.** With the authenticator off (an enrolment made with `OWNER_AUTHENTICATOR_REQUIRED=false`) there are **two** factors, not three: **a person who knows the three answers AND controls the owner's mailbox can act as the owner.** The recovery code never lowers that to one (it replaces the emailed code, and the questions are still required), but the phone is no longer a third barrier, so protect the mailbox (its own strong password and second step) accordingly. The mailbox address, the authenticator secret (when there is one), the question hashes and the recovery-code hashes are one sealed (AES-256-GCM) document in the database; the key is the file named by `OWNER_STORE_KEY_FILE`. A person or process running as the **same operating-system account** as SSO can read that file; the protection is running SSO as its own account and the file's ACL (the enrolment tool locks it down with `icacls`), and the seal keeps a database dump, a backup copy or a database write from revealing or forging the store (a write can only destroy it). Back the key file up separately from the database backup; without it the store cannot be opened (repair with `owner:recover`). The counters (failures, lock, authenticator replay guard, used recovery codes) are plain rows. Creating a tenant in DMS is covered separately (DMS verifies the same kind of authorisation, `dms.tenant.create`, with its own per-process single-use memory). Changes made by Active Directory synchronisation are not owner operations and are not covered. The owner tools are TypeScript source run with `tsx`, like the vault tool; they are **not part of the compiled production package** and need the source tree and `node_modules` on the server.

**Development and the mirror.** Development is unrestricted (`OWNER_VERIFICATION_REQUIRED` false). The mirror defaults to required: either enrol on the mirror database (`owner-enroll.ts` with the mirror launcher) or write `OWNER_VERIFICATION_REQUIRED=false` in `.env.mirror` on purpose (the mirror is then, knowingly, unrestricted).

**Turning the authenticator off on a server that is already enrolled with it.** Set `OWNER_AUTHENTICATOR_REQUIRED=false` in that environment's env file, then run `owner:recover` (vault password, or one recovery code) and enrol again; nothing changes until that run completes, and then the old questions, authenticator and recovery codes stop working at once. Leave the line in the file so that the next re-enrolment makes the same choice. A changed enrolment needs no restart of SSO (the store is read from the database); the new setting itself is read by the tool when it starts, and by a running SSO only after a restart (SSO uses it only to say what a new enrolment would need, never to verify).

**Rolling back.** `migrations/027_owner_verification.down.sql` drops the six tables; enrolment is lost and must be repeated.

## 17. 2026-10-19: tamper detection and incident response

**In one paragraph.** Two things watch for tampering. Inside SSO, an *incident response* notices refused owner-only operations, administrator-rights changes the owner did not make, and a broken audit log, and reacts by itself. Outside every application, a small *watcher* (`tamper.cjs`, plain Node, no installed packages; the watcher is not included in this edition, so the watcher paragraphs below describe the contract SSO is built to work with) checks the files, the scheduled tasks, the backups and the health of the whole server every five minutes and still works when the applications are down or have been taken over. Both do the same four things: write a protected record, alert the owner, end the offending person's sessions, and put the platform in **read-only** mode. Neither one ever stops a service, deletes anything, or rotates or destroys a key. Developing on a PC is never locked unless someone switches it on.

**What "read-only" means.** While the lock file exists (`INCIDENT_LOCK_FILE`, which a deployment points at `<data folder>\incident.lock`), SSO, GMS and DMS answer every change (POST, PUT, PATCH, DELETE) with `403 INCIDENT_READ_ONLY`. Reading keeps working. Sign-in, sign-out, health, the licence routes and, in SSO, the owner's own verification sequence, the signing-key routes and the acknowledgement of a known audit-log break (`POST /api/v1/admin/audit/chain-acknowledgements`) keep working, so the owner can still prove who they are, rotate a key and explain an old break. It is the same allowlist the licence uses when it has expired. The lock is a file with `{at, reason, kind}` in it and nothing secret. It is checked about every three seconds.

**What SSO does by itself** (the table is `POLICY` in `backend/src/ops/incidents.ts`; `INCIDENT_RESPONSE=contain|alert|off`, default `contain` in production and the mirror, `alert` elsewhere):

| What happened | Response |
|---|---|
| An owner-only operation refused three times in ten minutes by one person | end that person's sessions, lock |
| An owner-only operation attempted outside the verification sequence by someone who is not the owner | end that person's sessions at once; lock at the third. (The owner's own first attempt of every action is not an incident and is not recorded.) |
| A wrong answer or code in the owner sequence, or the sequence locking | recorded and counted only: the person failing may be the owner |
| Administrator rights change attempted by someone who is not the owner (refused) | end their sessions at once; lock at the third |
| Administrator rights actually changed without the owner (the membership no longer matches the owner's audit rows, or an audit row names someone else) | end their sessions and lock at once |
| The audit log no longer verifies | lock at once (evidence may be being destroyed) |

The owner's own session is never ended and the platform is never locked over the owner's own action. Every recorded incident is one row of `security_incidents` (migration 028): append-only (the database refuses changes) and hash-chained (an edited or removed row is found by verification), plus a `security.incident` line in the admin audit chain, an error line in the log marked `[idp:incident:ALERT]`, and one line in `incident-events.jsonl` next to the lock file for the watcher to e-mail. **Security incidents** in the console (owner only, read-only) lists them, shows the lock and whether the incident log verifies. It cannot lift a lock.

**Clearing a lock: only from a terminal on the server.** The watcher's `tamper.cjs clear` command prints what it will do, asks you to type `CLEAR INCIDENT LOCK`, removes the lock, resets the list of open findings and leaves an audit line and an alert. If the cause still stands (a changed file, say) the next check locks again: deal with the cause, or run `baseline` to accept an intended change, then clear. Removing the file by hand is detected as "lock removed while an incident is open" and the lock is written again.

**When the audit log is what locked it (2026-10-21).** "The audit log no longer verifies" locks at once, and an old, explained break (the mirror's two July 2026 entries, written with the v1 hash) is enough. The way out is in the console, **while locked**: Admin > Audit log, the platform administrator acknowledges each break (a real reason of 20 or more characters, kept forever) and completes the owner's verification for each one. That route is on the lock's allowlist (`INCIDENT_EXTRA_ALLOWLIST` in `ops/incidentGuard.ts`, an exact path) and nothing else is loosened: it is still the platform administrator's alone, still needs the owner's one-time authorisation (`audit.chain.acknowledge`) and the console's CSRF token, and it **never lifts the lock**. Before this fix the lock refused the acknowledgement, so the owner could not explain the break that had locked the platform (found on the mirror). What to expect, in order:
1. `npm run audit:verify` (production: `node scripts/run-with-env.cjs production npx tsx src/db/verify-audit-chain.ts`) before the cutover lists every break read-only; write the sequence numbers down. On the first start SSO will lock if any is open.
2. Acknowledge each one in the console. Explaining one of several records **no new incident**: only a break that was not open before, or more open breaks than before, raises `audit_chain_broken` again (`ops/auditChain.ts`; the mirror recorded a second incident at its first acknowledgement because the old key was "open count : first open break", which changes whenever one is explained). The acknowledgements and the owner-authorisation lines are themselves audit entries and the chain still verifies.
3. When every break is acknowledged the chain reads as verified with "N historical break(s) are on record and acknowledged". **The lock is still in force**: clear it from the terminal, `tamper.cjs clear`, as above. A break that cannot be acknowledged (`tail`, `empty`: recent entries are missing) is a real loss; restore from a backup rather than explaining it.
4. As a fallback only, on a build that does not yet have this fix, start SSO once with `INCIDENT_RESPONSE=alert` in its env file (records, does not lock), acknowledge, then remove the line and restart.
Tests: `tests/incident-ack-while-locked.test.ts` (the whole sequence on a scratch database), `tests/incident-guard.test.ts`, `tests/audit-chain-raise.test.ts`.

**The watcher: setting it up (once, by the owner, at a terminal).**

1. `tamper.cjs setup --root <checkout> --releases-dir <releases> --public-key <release public key> --expect-fingerprint <fingerprint>` asks for the SMTP host, port, user and password, the owner's mailbox and an optional webhook at **hidden** prompts and stores them **encrypted** (Windows DPAPI; `--scope machine` if the task will run as SYSTEM, `--no-email` for log only). Nothing is echoed or written in clear text.
2. When the platform is in the state you intend: `tamper.cjs baseline`. It records a SHA-256 of the start scripts, every script in the deploy folder, every file in the current release's operations folder, every env file in the config folder (the hash only, never a value), where the `current` junction points, and what each expected scheduled task runs. The baseline is signed with a local key kept in its own protected file. Run `baseline` again after every release you apply or other intended change.
3. `tamper.cjs test-alert`, then, **elevated**, the watcher's task-registration script (`register-task.ps1 -ScriptPath ... -ConfigDir ... -DataDir ...`) registers `ExampleCorp-Tamper-Watch` (at startup, then every five minutes). Nothing registers a task unless you run that script.

**What each pass checks:** the applied release against its signed manifest (the full hash of every file, every six hours); the protected files above; the scheduled tasks (present, enabled, action unchanged); the last backup (a warning past 36 hours); the health endpoints and the licence status; the watcher's own files and the baseline's signature; the incident lock; its own incident log. A critical finding writes the protected log (`<data>\tamper\incident-log.jsonl`, hash-chained, with a second copy of every hash in the config folder), writes the lock, and alerts through the Windows Event Log, e-mail and the webhook if set. A warning (stale backup, a service down, a release applied since the baseline) alerts but never locks. `tamper.cjs status` and `verify-log` show where things stand. Once a day the watcher takes an **anchor**: the head of the audit chain (a hash and a count, nothing else) is stored and e-mailed, and `tamper.cjs anchor verify` later proves the chain in the database was not rewritten. The anchor needs `OPS_WATCH_KEY_FILE` (the release tooling sets it) so SSO knows the watcher's key.

**Signing-key rotation is manual.** `tamper.cjs key-rotation-checklist` (it asks for a typed phrase) only prints the steps: the SSO Keys page, the licence-signing key, the release-signing key. The vault master key is never touched by anything here.

**What this cannot do.** Someone with administrator rights on the server can stop the watcher, remove its task, or rewrite both copies of its log; the e-mailed alerts and anchors are the copies they cannot reach, so keep them. A change made while the watcher is not running is found at the next pass, not as it happens (worst case five minutes). The SSO side sees what goes through SSO and its tables; it cannot see a change made to another system's database directly. The e-mail is only as reliable as the mail server; the log and the Event Log still record. If SSO itself is compromised it can lie to the anchor request, which is why the anchor history is kept elsewhere. Active Directory synchronisation is not an owner operation and is not covered.

**Development and tests.** Nothing here runs on a development PC unless started on purpose; the lock needs `INCIDENT_LOCK_FILE`, and the default response outside production is `alert`. Tests: `npx jest tests/incident` in `backend` (the database part needs `INCIDENTS_TEST_DATABASE_URL` pointing at a scratch database with the migrations applied), and the incident gate tests in GMS and DMS.

## 18. 2026-10-22: other applications, sign-out parity, sign-out address

- **Other applications (all optional; production and the mirror set none):** `MOS_ENABLED=true` registers the OIDC client `mos` (`MOS_CLIENT_SECRET`, `MOS_REDIRECT_URIS`, `MOS_LOGOUT_URIS` required; `MOS_PORTAL_URL` adds the tile; `MOS_BACKCHANNEL_LOGOUT_URI` is where SSO tells MOS someone signed out). `PRODUCT_CLIENTS_JSON` / `PRODUCT_APPS_JSON` register any other application and its portal tile (`oidc/product-clients.ts`; a malformed list stops the start; a client may carry `backchannel_logout_uri`). The `.env.example` files document every key.
- **Sign-out reaches those applications.** When a person signs out or is disabled, SSO POSTs a signed logout token (typ `logout+jwt`, audience = the client id, 2 minutes) to every registered `backchannel_logout_uri`, exactly as it does for DMS, retries failures for 48 hours (migration 029, kind `app-logout:<client id>`), and the disable warning names an application that did not answer. Each application verifies the token against SSO's keys and ends that person's sessions.
- **Per-user App access.** The user page in the console has an App access panel (the entitlements of the person's own group).
- **Sign-out address.** The sign-out page and its redirect are built for the issuer's own address, whatever Host the proxy chain reports (`oidc/end-session-origin.ts`). On the mirror, where Apache does not preserve the Host, the form used to post to the frontend's internal address and sign-out stalled. Check: `npm run verify:end-session-origin`.
- **Licences.** A client licence that may also run standalone (`modes` contains `standalone`) is not tied to SSO's end date; an SSO-only licence ends with SSO, with SSO's grace days capped at the client's own hard stop (`licenses/follow.ts`).
