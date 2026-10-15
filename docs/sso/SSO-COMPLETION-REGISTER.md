# SSO completion register (2026-10-11)

Written for: an auditor or reviewer who needs to know what was changed in SSO in the 2026-10-11 completion pass (two parts), how each claim was
checked, and what is **not** done. Nothing here is committed or deployed to the live server yet; the mirror (this checkout) runs it.

## 1. Evidence at the time of writing

| Check | Result |
|---|---|
| Backend `tsc --noEmit` | clean |
| Backend `npm test` | 39 suites, 334 tests, all pass |
| Frontend `tsc --noEmit`, `eslint .` | clean |
| Frontend Playwright (real browser, real backend, dev database) | 70 tests: 66 pass, 4 skipped on purpose (the platform-administrator specs, section 5). Run as one full suite, plus a re-run of `settings.spec.ts` after a test was updated for the new setting. |
| `npm run test:supervisor` | real child processes: restart, back-off, hung-process kill, lock, `--stop` (part 1) |
| Mirror rebuilt from this checkout and restarted under the supervisor | migrations 021 and 022 applied to `idpprod`; backend and frontend rebuilt; `/sso/health/ready` through Apache answers `ready` with the new `auditChain` check `ok`; `/sso/forgot-password` serves the form; the old `/sso/admin/...` paths that matched no page answer 404; `/metrics` answers 401 without the key, JSON by default and Prometheus text with `?format=prometheus` or `Accept: text/plain`. |
| Shipped-dependency audit | backend `node scripts/audit-gate.mjs`: passes, one dated exception (section 5); frontend `npm audit --omit=dev`: 0 vulnerabilities |

Not verified: anything on the live server (section 6); the platform administrator's own browser flows (section 5, they have no account on this machine).

## 2. Part 1: what changed

**Availability.** A supervisor (`deploy/supervise.cjs`) restarts SSO on any exit and kills and restarts one that is up but not answering `/health`; one supervisor per name (lock
file with heartbeat). Readiness returns 503 only for a failing database or signing key; every other dependency makes it *degraded* (HTTP 200) so a monitor does not pull a working
identity provider out of rotation. Rate limiters fail open when their store fails. Password hashing is bounded (concurrency, queue, wait); past the bound a sign-in gets 503 "busy",
never "wrong password" and never a counted failure. Sign-out notices to DMS and GMS that fail are queued and retried for 48 hours (migration 020).

**Configuration from the console.** Admin > Settings: password rules, lockout, two-factor for administrators, token and session lifetimes, retention, branding, portal message. Env values
are defaults; a stored value wins and applies without a restart. Every change is validated and audited with old and new value. Platform-administrator-only settings are enforced on the
server, not only hidden in the UI (`tests/settings-api.test.ts`).

**Applications.** Admin > Applications: addresses, enable/disable, secret rotation, details; read live by oidc-provider through the adapter (no restart). The `portal` client is protected.

**Accounts.** Two-factor recovery codes; bulk user actions; filters and CSV export (spreadsheet formulas neutralised); a user page with last sign-in, lock state, recent attempts, readable
change history, a temporary-password generator that follows the real minimum, and confirmation before a password reset or removing two-factor.

**Console and browser security.** Every list has loading, error and empty states; audit and sign-in pages filter on the server; System health page; role-aware navigation. Platform-administrator
invisibility is **intentionally one-way**: no "show platform administrator" switch exists or should. Nonce-based Content-Security-Policy (`SSO_CSP=report-only|off` break-glass), frame, sniffing,
referrer and permissions headers; double-submit CSRF tokens reused while the cookie lives; log redaction.

**Delivery.** `production-start.bat` and `start-mirror-all.ps1` start SSO supervised; CI uses the dated-exception audit gate; runbook in `SERVER-DEPLOYMENT-TODO.md` section 13 and
`SSO-OPERATIONS.md` sections 13 and 14.

## 3. Part 2 (the open items from part 1, worked through)

| Part 1 open item | What was done |
|---|---|
| Legacy server-rendered `/admin` console still mounted (SSO-P2-5) | **Retired.** Routes, `requireAdminConsole`, `admin/csrf.ts` and the frontend's `/admin/*` rewrite are deleted. `admin/router.ts` was split: what the JSON API and the seed scripts share is `admin/access.ts` (977 lines kept, about 1,600 removed). Nothing in the console called the old routes (every page uses `/api/v1/admin/*`, checked page by page). |
| Audit chain has no "acknowledge break" | **Built.** The verifier now reports every break and carries on past one (it used to stop at the first). `hash`, `linkage`, `ordering` and `head` breaks can be acknowledged by the **platform administrator only**, with a reason of at least 20 characters. The acknowledgement is pinned to the row's stored hashes **and** a content fingerprint (so a row edited again is a new break, which DMS's version does not guarantee), is itself appended to the chain in the same transaction, and never hides the break. `tail` and `empty` breaks (recent entries missing) cannot be acknowledged. A job verifies every six hours; an unexplained break turns the System page and `/health/ready` to degraded (200), sets `sso_audit_chain_valid 0` and logs an alert. Migration 021. 12 chain tests against the real writer, 10 HTTP tests for who may do what. |
| No Prometheus endpoint | **Built.** `GET /metrics?format=prometheus` (or a scraper's Accept header; JSON stays the default). 36 metric families covering readiness, jobs, password-check load, notifications, peers, breakers, pool, audit chain, supervision and request counts/latency by a fixed set of areas (bounded labels). Same access rule as before (administrator, `x-metrics-key`, or the public flag). |
| No forgot-password flow | **Built within the no-SMTP limit.** "Forgot your password?" on the sign-in page sends a request to the administrators (Admin > Users lists who is waiting and what they wrote); the reset itself is the existing administrator reset, which closes the request. The public answer never depends on whether the account exists; only active local accounts get a request; Active Directory accounts and the platform administrator never do; rate limited (5 per 15 minutes per address); can be switched off in Settings. Migration 022. |
| SSO is single-process | **Made safe to run as more than one, without claiming it is the plan.** Signing keys now follow the table every 30 seconds (a rotation from another process, or a retired key's overlap ending, used to wait for a restart: a real defect even with one process, because a retired key stayed published until restart). The purge and AD re-check sweeps take a Postgres advisory lock so two processes do not double up. What stays per process, and the need for `REDIS_URL` for shared rate limits, is written down (`SSO-OPERATIONS.md` section 14). The supported availability model is still one supervised process. |
| Groups and DMS-roles pages not redesigned | **Done.** Groups: server-side search by name, readable group names, what each group opens, empty and error states with retry; the group page disables Save until something changed and, for a group with members, asks first and says how many people are signed out (the server already signs them out on a real change). DMS Roles: filter, counts, honest states. |
| Frontend dev-toolchain advisories (9) | **Evaluated, not changed (section 5).** |
| Platform-admin paths have no real-browser test | **Prepared, cannot run here (section 5).** `e2e/platform-admin.spec.ts` runs when a platform administrator exists on the dev database. |

**Found and fixed on the way (disclosed):**
- Admin "create user" and "reset password" accepted any password of 8 characters. The platform password rules (`password.minLength`, the common-password list, the sign-in-name rule) now apply to a
  temporary password too; before, a platform setting of 12 was enforced everywhere except where an administrator typed a password. Tests added.
- A retired signing key stayed published by a running process until it restarted, because only a rotation reloaded the keystore (fixed by the 30-second refresh above).
- The dev database has ten audit entries from July 2026 that no longer recompute under the current dev secret. Before, that read as one "CHAIN BROKEN" and hid whether anything else was wrong; now every
  break is listed and the ten are acknowledged by `npm run db:ack:dev-audit` (dev only, refuses on production and the mirror). The mirror's chain is clean.
- The Next dev server kept an old server-side module after a change until restarted (the new branding flag was silently dropped). Noted in `SSO/CLAUDE.md` so the next person restarts before debugging.
- A page whose first load fires several requests at once can hold a CSRF token the cookie no longer matches; the new Users card fetches a fresh token before it posts.

## 4. Earlier findings fixed during verification (part 1)

A second browser tab silently losing its CSRF token; the users page application filter breaking when the clients endpoint changed shape; a "locked until" display using a wrong condition (now a
server-computed `isLocked`); hydration races in the e2e login (a `data-hydrated` wait); a system-health test that rejected the harmless field name `passwordChecks`.

## 5. Open items, stated plainly

| Item | State | Why it is accepted or deferred |
|---|---|---|
| `braces` advisory (high) | Accepted until **2027-01-31** in `scripts/audit-gate.mjs` | No fixed version exists upstream (3.0.3 is the latest and is affected); reached only through `http-proxy-middleware` with fixed paths. |
| Frontend dev-toolchain advisories (9: `braces` through `fast-glob` and `micromatch`, and tailwind 3's `chokidar`, `postcss-nested`, `postcss-selector-parser`) | Open, build-time only | `npm audit --omit=dev` reports 0. Checked 2026-10-11: moving to Tailwind 4 would clear the postcss and chokidar chain but **not** `braces`, because the latest `eslint-config-next` (16.4.0) still pins `@next/eslint-plugin-next` to `fast-glob 3.3.1`, which pulls `micromatch` and `braces`. No version of the tree reaches zero until `braces` is fixed, and Tailwind 4 is a CSS migration with real regression risk for no audit gain. Revisit when `braces` has a fix. |
| Platform-administrator browser tests | Written, **never run** | The dev database refuses to create a platform administrator without the vault, and the vault and account passwords are only typed at a terminal on purpose (`scripts/seed-platform-admin.ts`). `e2e/platform-admin.spec.ts` skips itself with the reason unless `SSO_E2E_PLATFORM_EMAIL` and `SSO_E2E_PLATFORM_PASSWORD` name one. The same rules are proved over HTTP with the gate mocked (`settings-api`, `clients-api`, `audit-chain-api` tests). The specs' selectors come from reading the pages, not from running them. |
| Acknowledging a break in a real browser | Not exercised in a browser | It is the platform administrator's alone (same reason). The browser tests prove an ordinary administrator sees the list, gets no button, and is refused over the API. |
| Password reset needs a human | By design | No SMTP. The request reaches the administrators; they reset and tell the person. If SMTP is ever added, the link flow can replace the human step without changing the request table. |
| More than one SSO process | Safe, not the plan | Rate limits need `REDIS_URL` to be shared; the password gate, circuit breaker and peer probes are per process (section 14 of the operations manual). |
| Audit-chain `tail`/`empty` breaks | Cannot be acknowledged, by design | They mean recent entries are missing; the answer is a restore. |
| Live server | **Not deployed** | The owner applies `SERVER-DEPLOYMENT-TODO.md` section 13 (six migrations, 017 to 022), including the outage test. `LOCAL_JWT_MOCK` in the live DMS `.env.production` is still unread (see root `CLAUDE.md`). |

## 6. Owner decisions that remain

1. Deploy to the live server (backup first). 2. Whether to turn on "Require two-factor for console administrators" once every administrator has enrolled. 3. Whether to keep "Forgot your password?"
on (it needs someone to look at Admin > Users). 4. Whether to create a dev platform administrator so the platform-administrator browser specs can run. 5. Whether to set `METRICS_API_KEY` and point a
Prometheus at SSO.

## 7. Where to look

`SSO-OPERATIONS.md` sections 13 and 14 (running it), `SERVER-DEPLOYMENT-TODO.md` section 13 (deploying it), `SSO/CLAUDE.md` "Added 2026-10-11" (two parts: things that bite),
`backend/docs/TEST_STATUS.md` (generated test list), `backend/docs/API.md` (JSON API, including the new endpoints), `backend/src/admin/audit.ts` (the chain and the acknowledgement).
