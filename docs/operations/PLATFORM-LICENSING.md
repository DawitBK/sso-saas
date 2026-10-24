# Platform licensing (SSO, GMS, DMS)

Status: design contract, 2026-10-19 (sections 4.1 and 10 revised 2026-10-21). One licence per system, **issued and managed centrally in SSO**,
checked by each system. Design decisions: central in SSO; on expiry **warn, then a grace period, then read-only**; a licence controls **expiry, a
seat limit and enabled modules**. Written so the three systems can be built in parallel and still agree.

This document is the same in the SSO, GMS and DMS editions. Sections 1 to 10.1 are identical in all three and name no file paths; section 11
lists where the rules are implemented in the edition that holds this copy.

## 1. Principles (read before changing anything)

1. **No licence record = no enforcement.** State `unconfigured`: everything works and **nobody sees any notice** ("no licence configured" is shown
   nowhere, in no system). Deploying this to a server that has no licence yet must change nothing for its users. A system may hold real production
   data; a licence feature must never be able to lock it by accident.
2. **Never block because SSO is unreachable.** A consumer keeps the last verified token (in memory and on disk) and keeps
   enforcing *that token's own dates*. If it has never fetched one, it is `unknown` and does not enforce. Fail open on
   transport, fail closed only on a verified, expired token.
3. **Read-only, never data loss.** Expiry never deletes, disables or alters accounts or data. Existing users are never
   deactivated by a seat limit; only *creating or activating* beyond it is refused.
4. **Platform administrators and licence administrators are never locked out of managing the licence.**
5. Server clock is the time source (clock tampering is out of scope).

## 2. The licence record (SSO table `licenses`, one row per system)

`system` ('sso' | 'gms' | 'dms', unique), `customer` (text), `expires_at` (timestamptz, **NULL = perpetual**),
`grace_days` (int, default 14, 0..365), `warn_days` (int, default 30, 0..365), `max_users` (int, NULL = unlimited),
`modules` (text[] of enabled **gateable** module keys; NULL = all enabled), `notes`, `version` (int, the issue time: see 4.1),
`created_at`, `updated_at`, `updated_by`. Plus an append-only `license_events` table (who, when, system, action
`create|update|extend|revoke`, before/after JSON), also written to the SSO audit trail. "Revoke" deletes the active record
(returns the system to `unconfigured`) and keeps the event row.

## 3. States (computed, same function in all three systems)

With `now`, `expires_at`, `grace_days`, `warn_days`:

| state | when | effect |
|---|---|---|
| `unconfigured` | no record | none |
| `unknown` | consumer has never obtained a verified token | none |
| `active` | perpetual, or `now < expires_at - warn_days` | none |
| `expiring` | `expires_at - warn_days <= now < expires_at` | banner only |
| `grace` | `expires_at <= now < expires_at + grace_days` | banner only, full function |
| `expired` | `now >= expires_at + grace_days` | **read-only** |

`daysRemaining` is whole days to `expires_at` (negative after it); `graceEndsAt = expires_at + grace_days`.
Module gating and seat limits apply in every state **except** `unconfigured` / `unknown`.

## 4. The signed token (SSO -> consumers)

SSO signs a compact JWS with its existing OIDC signing key (the one published at its JWKS), `alg` RS256, header
`typ: "kcms-license+jwt"` and the key's `kid`. **Payload** (no `exp` claim on purpose: the licence's own dates are the
expiry; consumers must not reject on token age):

```json
{ "iss": "<SSO issuer>", "aud": "license:gms", "sys": "gms", "ver": 7, "iat": 1792394000,
  "customer": "Example Corp", "expiresAt": "2027-01-01T00:00:00.000Z" /* or null */,
  "graceDays": 14, "warnDays": 30, "maxUsers": 50 /* or null */, "modules": ["visits","scheduling"] /* or null = all */ }
```

Consumers verify: signature against SSO's JWKS (RSA JWK via `crypto.createPublicKey({key, format:'jwk'})`, no new
dependency needed), `typ`, `iss`, `aud === license:<their system>`, `sys`. Anything else is rejected and the previous good token
is kept. A token with a lower `ver` than the one held is ignored.

### 4.1 The version rule (`ver`): newer issue time wins (2026-10-21)

`ver` is the **time the licence was issued**, as whole **seconds since 2026-01-01 00:00:00 UTC** (`max(1, floor((issueTimeMs - Date.UTC(2026,0,1)) / 1000))`). Every channel uses it, so the licence issued **last** has the highest `ver` and wins in every system, however it was issued. There is no counter and no list of numbers to keep. The rule lives in one dependency-free module of SSO's licences code (`versionFromTime`, `nextLicenseVersion`). Consumers need no change: they already compare `ver` as a plain number (keep the highest, ignore a lower one).

- **Console (SSO service):** the next version for a system is `max(highest version that system ever had + 1, versionFromTime(now))`. It is strictly increasing even if the clock steps back, in the same second, and across a revoke (a revoke takes a version too).
- **Offline signer (the SSO edition's `license:sign` script):** `--version` is optional and defaults to `versionFromTime(now)`. It prints on stderr the version, the issue time it names and `This replaces every <system> licence issued before <time>`; stdout is the token only. An explicit `--version <n>` (a whole number, 1 to 2147483647) is accepted as a **recovery tool only**, for example to beat a version issued by a machine whose clock was set wrongly.
- **Development issuer (the SSO edition's `license:dev-issue` script):** the same rule as the console.
- **Range:** a 32-bit signed integer (the `licenses.version` and `license_events.version` columns are INTEGER), good until 2094. Plain Unix seconds are not used because they overflow in 2038.
- **Keep the issuing PC's clock correct.** A clock set far into the future issues a very high version that later correct-clock licences cannot beat; recover by signing with an explicit `--version` above it.
- **Resolution is one second.** The console never issues the same version twice for a system, but a console save and an offline signing in the very same second would carry the same `ver` (a consumer keeps the one it saw first). Issue one, wait a moment, then the next.
- **Older counters.** Counter-style versions (1, 2, 3 ... hand-typed or counted) are all far below any time-based version, so the first licence issued under this rule supersedes every older one in every system. Nothing needs converting and nothing is tracked by hand.

## 5. Endpoints

**SSO backend** (all under SSO's `/api/v1` prefix):
- `GET /api/v1/licenses/public/:system`: **unauthenticated**, rate-limited; `200 {token}` or `404` if none. The token holds no secret.
- `GET /api/v1/licenses/status`: SSO's own status (section 6 shape); **platform administrator only** (403 for an IdP administrator: licences are neither controlled nor viewed by anyone else).
- Admin (SSO admin console, platform administrator only; audited), under `/api/v1/admin/licenses`: list, upsert, `POST .../:system/extend`
  `{days}` or `{expiresAt}`, revoke. Validation: dates are real, `grace_days`/`warn_days` 0..365, `max_users` >= 1, module
  keys must be in the catalogue (section 7).

**Every system, including SSO:** `GET /api/v1/license/status` (any authenticated user; GMS keeps its unprefixed `/api/v1`):

```json
{ "system":"gms","state":"grace","customer":"Example Corp","expiresAt":"...","graceEndsAt":"...","daysRemaining":-3,
  "warnDays":30,"graceDays":14,"readOnly":false,"maxUsers":50,"seatsUsed":41,"modules":["visits"]|null,
  "source":"sso"|"cache"|"none","fetchedAt":"...","version":7 }
```

## 6. Consumer behaviour (GMS, DMS) and SSO's own

- **Fetcher:** poll `GET {LICENSE_SSO_URL}/api/v1/licenses/public/<system>` at start and every `LICENSE_POLL_SECONDS`
  (default 300), 5 s timeout, never throws into request handling; persist the last good token to a small file under the
  system's data dir so a restart while SSO is down still enforces it.
- **Read-only guard (state `expired` only):** a middleware refuses `POST/PUT/PATCH/DELETE` with HTTP **403** and the
  system's usual error shape, code `LICENSE_EXPIRED`, message "The licence has expired; the system is read-only. Contact
  your administrator." **Allowlist** (must keep working): sign-in/out/refresh/2FA/password-reset/SSO callbacks and bridges,
  health/readiness, `license/status`, and the read-only `POST`s that are really queries (search, etc.); each system lists
  its own, with a test per entry. Safe methods always pass.
- **Module gate:** a gateable module not in `modules` answers **403 `LICENSE_MODULE_DISABLED`** on its routes; core routes
  are never gated. Frontends hide the matching menu entries using `license/status`.
- **Seat limit:** creating or activating an account (UI, bulk import, JIT provisioning from SSO) when `seatsUsed >= maxUsers`
  answers **403 `LICENSE_SEAT_LIMIT`**; platform administrators are excluded from the count and from the refusal.
- **Config (all optional, in the env schema with these defaults, and in each `.env.example` / production template):**
  `LICENSE_ENFORCEMENT=enforce|warn|off` (default `enforce`; `warn` computes states and logs/banners but never blocks;
  `off` skips the fetcher entirely), `LICENSE_SSO_URL` (the SSO backend's loopback base URL, default `http://127.0.0.1:7300`;
  a production-like mirror environment points at its own SSO, `http://127.0.0.1:9300` in the shipped examples), `LICENSE_POLL_SECONDS`.
- **Frontends:** a banner for `expiring` / `grace` / `expired` (and nothing at all on `unconfigured`), read-only
  messaging when an API call answers `LICENSE_EXPIRED`.
- **SSO enforces its own licence** from its database (no token): the same read-only guard on SSO's admin mutations, with the
  allowlist covering sign-in, OIDC endpoints and token issuance (login must keep working), the portal, health, and the
  licence admin routes themselves.

## 7. Module catalogue (the keys; core is never gateable)

- **GMS:** `visits` (visits, approvals, guests, hosts), `scheduling`, `checkin` (check-in, UniFi webhooks), `credentials`,
  `notifications` (notifications, messages), `ocr`. Core: auth, users, offices, departments, services, operations.
- **DMS:** `letters`, `workflow` (workflow, approvals), `esigning` (esigning, signing), `legal_hold`, `retention`, `ai`
  (ai, assignment-advisory), `ocr`, `search`, `archive`, `reports`, `bundles`, `webhooks`, `forms`.
  Core: documents, folders, versions, document-types, access-rules/acl, roles, users, org-units, departments, tenants, audit,
  auth, comments, notifications, operations, feature-flags.
- **SSO:** none gateable (expiry and seats only).

The catalogue lives in SSO (its licences catalogue module) for the admin form, and each consumer keeps the same keys next to its
route gating; a test in each consumer pins its list to this document.

## 8. What an operator does

SSO admin console -> Licences -> pick the system, set customer / expiry (or "never") / grace / warn / seat limit / modules,
save; **Extend** adds days. Systems pick the change up within `LICENSE_POLL_SECONDS`. To turn enforcement off in an emergency:
`LICENSE_ENFORCEMENT=warn` in that system's env and restart.

**Owner verification.** In production and the mirror, saving, extending or removing a licence in the console also needs the owner's one-time authorisation (security questions, an emailed code or a recovery code, and the authenticator only when the enrolment was made with it: a new enrolment includes it only when `OWNER_AUTHENTICATOR_REQUIRED` is `true`, which is not the default; see "owner verification" in the SSO edition's operations guide). The console asks for it in a window when you press the button; until the owner has enrolled, these actions are refused (`OWNER_NOT_ENROLLED`), so enrol before the first licence is saved on a server. **Offline signing (the SSO edition's `license:sign` script) and installing a signed token on a consumer are not affected**: they do not go through the console. Reading a licence, the public token endpoint and every consumer's polling are unchanged.

## 9. Per-application entitlement (design decision 2026-10-19: each system is licensed on its own)

Sections 1 to 8 describe expiry. This section adds **entitlement**: whether a system may be used at all. It is a layer on top of the state
function (section 3, **unchanged**) and it supersedes principle 1 ("no licence record = no enforcement") **only where `LICENSE_REQUIRED` is true**.
Everything below is the contract; GMS, DMS and SSO implement it independently and none of them needs SSO to be running to honour a licence.

### 9.1 Switch, trust and token sources

**Switch.** `LICENSE_REQUIRED=true|false`. Default: `true` when `NODE_ENV=production` (live and the mirror), `false` otherwise (development and tests keep
working exactly as before). `LICENSE_REQUIRED=false` in a production process is logged at error level at every start.

**Trust (who may sign).** `LICENSE_TRUST_PUBLIC_KEYS` is a JSON array of **public** JWKs (RS256). When `LICENSE_REQUIRED` is true these are the ONLY keys
that verify a licence: SSO's JWKS is no longer trusted for licences, so neither a fake SSO nor a compromised network path can mint one, and the
key can be a **dedicated licence-signing key that never touches any server** (the licence issuer signs offline; see 9.3). When `LICENSE_REQUIRED` is false and
the variable is set it is used; unset, the old JWKS behaviour remains. Development and production use different keys, therefore different values.
Required and no key configured: no token can verify, so the system is unlicensed (and the boot log says why).

**Where the token comes from (any of these, the newest issue wins: the highest `ver`, which is the issue time, section 4.1; a lower `ver` is ignored).**
1. A token the system already verified and stored (survives restarts and SSO outages; a system keeps enforcing its own token's dates).
2. `POST /api/v1/license/install` with `{ "token": "<jws>" }`: unauthenticated on purpose (the signature is the authority; an operator may have no login yet),
   verified exactly like a fetched token, rate-limited, never lowers the stored `ver`.
3. The SSO poll (`GET {LICENSE_SSO_URL}/api/v1/licenses/public/<system>`), as today: a renewal channel, not a requirement. An SSO answer of **404 for a
   token that SSO itself had served means the licence was removed or revoked**: the stored token is dropped (required: the system is then unlicensed;
   not required: it returns to `unconfigured` and nothing is enforced). A token that was only ever **installed** (offline-signed; SSO may never have heard
   of it) is never dropped by a 404, otherwise the next poll would kill every offline licence. An unreachable SSO (timeout, 5xx, network) never drops anything.
   The origin of the held token (served by SSO, or installed) is persisted with it.

**Claims added to the token.** `modes`: array of `"sso"` and/or `"standalone"` (absent or empty means `["sso"]`). `jti`: unique id of this issued token (audit).

### 9.2 Deployment mode, entitlement and guard

**Deployment mode (computed by each system, never by the client).** `sso` when the system's SSO integration is configured, otherwise `standalone`.
A standalone deployment is entitled only when `modes` contains `standalone`. "Configured" means: **DMS** OIDC_CLIENT_ID, OIDC_CLIENT_SECRET,
OIDC_REDIRECT_URI and AUTH_ISSUER all set (LOCAL_JWT_MOCK never counts as SSO); **GMS** SSO_INTERNAL_API_KEY set, or SSO_API_BASE together with
SSO_ROLES_API_KEY; **SSO** is always `sso` (it is the identity provider).

**Entitlement function** (pure; one per system):
- `LICENSE_REQUIRED` false: always licensed (today's behaviour).
- required, no verified token (`unconfigured` or `unknown`): **unlicensed, reason `NO_LICENSE`**.
- required, token verified, `modes` does not contain the computed mode: **unlicensed, reason `MODE_NOT_LICENSED`**.
- otherwise licensed. Expiry is then the existing state machine (`expired` = read-only, never a deletion).

**Guard.** Required and unlicensed: every request answers **403 `LICENSE_REQUIRED`** except health/readiness, the licence status and install routes,
sign-in endpoints and, in SSO, the OIDC endpoints for the `portal` client. Exact exempt lists: **DMS** the whole `/auth` tree (tenant selection and 2FA must
not be cut off mid sign-in), the SSO role-lookup POST (`/internal/roles/.../role-mappings/resolve`, which SSO calls on every token issuance and which must not
start returning wrong roles), operations health/readiness, licence status and install, backchannel logout; **GMS** login, refresh, logout, `me`,
`/auth/verify-2fa`, the SSO callback, health, licence status and install; **SSO** its existing allowlist (sign-in, portal, bridges, health, licence and key
routes, internal) with every non-portal OIDC authorize refused. Static assets are served by the frontends, so the API has nothing to exempt for them. Nothing is deleted
and nothing is deactivated; installing a valid token restores service within one request. `LICENSE_ENFORCEMENT=warn|off` still behaves as the documented
emergency brake (logs what it would have refused / does nothing) and is reported at error level at every start while `LICENSE_REQUIRED` is true.
A failure inside the guard lets the request through (a licence bug must not lock live data) and logs at error level.

**Install route behaviour** (GMS and DMS, `POST /api/v1/license/install`): a valid token answers 200 and is persisted; a token with a lower `ver` than the
held one answers 200 with `installed: false` / `outcome: "ignored-older"` (never an error, never a downgrade); a bad signature, wrong `sys`/`aud` or
unknown mode answers 400 `ERR-LICENSE-INVALID`; no usable trust key answers 503. Limits: 10 requests per minute per address in DMS, 10 per 15 minutes in GMS.

**Status payload additions** (`GET /api/v1/license/status`): `required: boolean`, `licensed: boolean`, `reason: "NO_LICENSE" | "MODE_NOT_LICENSED" | null`,
`deployment: "sso" | "standalone"`. Frontends show **"This system is not licensed. Contact your administrator."** when `required && !licensed`; the old
"no licence configured" wording is never shown anywhere.

### 9.3 Signing keys and provisioning

- SSO signs with a **dedicated licence key** when `LICENSE_SIGNING_KEY_FILE` points at a PEM private key (RS256, `kid` = the key's JWK thumbprint); otherwise
  it keeps signing with the OIDC key (development convenience). For production the licence issuer may instead **sign offline** with the SSO edition's `license:sign` script
  (it reads the private key from a path the issuer types and prints the token) and upload the token in Admin > Licences or POST it to a system's install route:
  then the private key exists on no server.
- The SSO edition's `license:keygen` script (`--out <dir>`) makes a key pair for **development and the mirror** (private PEM into `<dir>`, which must be outside the repository;
  the public JWK is printed for `LICENSE_TRUST_PUBLIC_KEYS`). The production key is generated by the licence issuer at a trusted terminal and is never shown to, or stored on, any server or automated tool.
- Renewal = a new token issued later, which by 4.1 has a higher `ver` (Admin > Licences > Extend, or sign offline again with no `--version`); revocation = Remove in the console (SSO then answers 404) or
  letting `expiresAt` pass; a revoked or removed licence cannot be replayed because installation never lowers `ver` and a system's `ver` is never reused (4.1).
- Revocation reaches a system within `LICENSE_POLL_SECONDS` while SSO is reachable. A system that cannot reach SSO keeps its last token until that token's own
  dates run out, so choose `expiresAt` (and renew) with that delay in mind.

### 9.4 Rollout rule

Because `LICENSE_REQUIRED` defaults to true in production, **a production system with no installed licence is unusable**. Never deploy to a server before a
valid token for each system is installed or installable. In development and the mirror, the SSO edition's `license:dev-issue` script writes licence rows straight into SSO's database so the systems can be exercised.

## 10. Clients follow SSO's own expiry (design decision 2026-10-21)

GMS and DMS stop when SSO's licence stops, whether or not they have a date of their own, **unless their licence also allows standalone running** (the "May also run standalone (without SSO)" switch on the licence, `modes` containing `standalone`): a licence valid only behind SSO ends with SSO; a licence that may also run without SSO keeps its own dates and SSO's end date is none of its business (this applies in section 10.1 too). `GET /licenses/public/<system>` serves a client the token built from its own row, except that when SSO's own licence has an expiry earlier than the client's (or the client never expires) and the licence is SSO-only, the token carries **SSO's expiry and warning days, and SSO's grace days capped so the hard stop (expiry plus grace) is never later than the client's own** (SSO's licences code, "follow" module). The client therefore warns, enters its grace period and goes read-only together with SSO, and goes back to its own date when SSO is renewed or its licence is removed. The served `ver` is never lower than SSO's highest version ever, so every change to SSO's licence, including removing it, reaches the clients (a consumer ignores a lower version). A licence installed by hand at a client (section 9, offline signing) is not rewritten by that mechanism, which needs the licence private key on the server (the mirror setup).

### 10.1 Offline licences that still follow SSO: the "SSO ends on this date" note (design decision 2026-10-21)

With production's offline licences (private key on the issuer's computer only) GMS and DMS trust only the issuer's public key, so SSO cannot re-sign a client licence. Instead:

- SSO serves `GET /api/v1/licenses/public/sso-expiry` (unauthenticated, rate-limited): a compact JWS, `typ: kcms-license-ceiling+jwt`, `aud: license:ceiling`, `sys: sso`, claims `ver` (SSO's highest version ever, so it never goes down), `expiresAt` (null = never), `graceDays`, `warnDays`, `customer`, `iss`, `iat`; no `exp`; signed with SSO's ordinary OIDC key (published at `/jwks`), never with `LICENSE_SIGNING_KEY_FILE`. 404 `ERR-LICENSE-NOT-FOUND` when SSO has no licence.
- GMS and DMS (only in the `sso` deployment mode, never standalone) poll it beside their own licence (same interval), verify it against SSO's JWKS and issuer, and enforce the **earlier** of their own licence date and the note's date, but only for a licence valid solely behind SSO (`modes` without `standalone`); when SSO's date binds, SSO's warning days apply and SSO's grace days are capped so the system never stays usable past the end of its own licence's grace period. The status answer gains `limitedBy: "licence" | "sso"` (additive).
- **It can only shorten.** The client's own offline-signed date is the hard backstop and only the issuer's private key can extend it, so a forged or replayed note can end a system early at worst, never extend it. The hard backstop should therefore be a real date (for example 12 months), not "never".
- A client keeps the last note it verified (memory plus a cache file: GMS `sso-expiry.json` beside `last-token.json`, DMS `<cache>.sso-expiry`), re-verified at boot against the key stored with it, so blocking SSO cannot bring an ended system back. An unreachable SSO, a bad answer or an older `ver` changes nothing. Only SSO's own "no licence record" answer (`404` with `error.code = ERR-LICENSE-NOT-FOUND`) drops the note; any other 404 (an unknown route, a gateway, a proxy, an SSO mid-update) does not. In the offline setup do NOT save GMS or DMS rows in the SSO console: SSO would then serve IdP-signed client tokens that the pinned clients (rightly) reject, with a warning every poll.
- Where both mechanisms are active (the mirror) the two dates are equal.
- **Tenants.** A DMS licence covers the whole installation, every tenant on it. When SSO ends, a DMS that follows it ends for all its tenants together. That is the intended reading of "one organisation, one SSO". SSO itself has one directory and one licence; it is not multi-tenant. Hosting several unrelated customers on one SSO would need a separate sign-in realm and licence per customer, a design change of its own (an open question; nothing in the code depends on it today). Until then a customer whose system must outlive SSO's licence needs a licence with the standalone switch on.

## 11. Where this edition implements it

This copy is in the SSO edition, which is the **issuing** side of the contract: it holds the licence records, signs the tokens and serves the
public endpoints. Paths are relative to the repository root.

- Records, save, extend, revoke, validation (sections 2 and 5): `backend/src/licenses/service.ts`, `backend/src/licenses/validation.ts`, `backend/src/licenses/repository.ts`
  and the tables in `backend/migrations/025_licenses.sql` and `backend/migrations/026_license_modes.sql`.
- State function (section 3): `backend/src/licenses/state.ts`.
- Signed token and the version rule (sections 4 and 4.1): `backend/src/licenses/token.ts`, `backend/src/licenses/version.ts`.
- Endpoints (section 5): `backend/src/api/v1/licenses.router.ts`; the OpenAPI text is in `backend/src/api/v1/openapi.ts` and the route tables in `backend/docs/API.md`.
- SSO's own status and read-only guard (section 6): `backend/src/licenses/status.ts`, `backend/src/licenses/guard.ts`, `backend/src/licenses/enforcement.ts`.
- Module catalogue (section 7): `backend/src/licenses/catalog.ts`.
- Entitlement (section 9): `backend/src/licenses/entitlement.ts`.
- Following SSO's own expiry (sections 10 and 10.1): `backend/src/licenses/follow.ts` and `backend/src/licenses/ceiling.ts`.
- Offline signing, key generation and the development issuer (sections 9.3 and 9.4): `backend/scripts/license-sign.ts`, `backend/scripts/license-keygen.ts`,
  `backend/scripts/license-dev-issue.ts` (npm scripts `license:sign`, `license:keygen`, `license:dev-issue` in `backend/package.json`).
- Admin console and banner: `frontend/app/admin/licenses/page.tsx`, `frontend/shared/components/LicenseBanner.tsx`, `frontend/shared/lib/license.ts`.
- Settings: `backend/.env.example` and `backend/.env.production.example` (`LICENSE_ENFORCEMENT`, `LICENSE_REQUIRED`, `LICENSE_SIGNING_KEY_FILE`).
- Tests: `backend/tests/licenses-catalog.test.ts` pins the catalogue to section 7 of this file; `backend/tests/license-version.test.ts` (section 4.1),
  `backend/tests/license-signing.test.ts` (sections 9.1 and 9.3), `backend/tests/license-follow-sso.test.ts` and `backend/tests/licenses-api.test.ts` (sections 5, 10 and 10.1),
  `backend/tests/licenses-state.test.ts`, `backend/tests/licenses-validation.test.ts` and `backend/tests/license-guard.test.ts`.
- Running it, and owner verification for console changes: [the SSO operations guide](../sso/SSO-OPERATIONS.md), section 15 (platform licensing) and section 16 (owner verification).

GMS and DMS are the consuming editions of this contract; each keeps its own copy of this document.
