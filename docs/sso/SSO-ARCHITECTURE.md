# Example Corp SSO — Architecture

Status: implemented (IdP + DMS + GMS) · 2026-07-05 · owner: platform

This document answers the "how does this actually fit together" questions:
public vs authenticated access, internal vs external users, legacy (PHP / plain-JS)
integration, whether we need a gateway/shell or microservices, and where the
seams are.

---

## 1. The one idea that makes this simple: **two identity planes, not two systems**

We are **not** splitting anything into microservices, and we are **not** forcing
every request through a front door. Each app stays exactly what it is today (a
modular monolith with its own DB). We add **one** shared service — the IdP — and
apply it **selectively**.

Every app already serves two kinds of caller. Keep them separate at the *auth*
level, not the *deployment* level:

| Plane | Who | How they authenticate | Touches the IdP? |
|-------|-----|------------------------|------------------|
| **Internal** | Staff / employees (DMS: EMPLOYEE…SYSTEM_ADMIN; GMS: host, reception, admin, super_*) | **SSO** via the IdP (OIDC, or the GMS token bridge) | Yes |
| **External** | GMS guests, DMS external document signers, anyone verifying a printed letter (`/letters/verify`) | Each app's **existing native / public flow** — email+OTP, a signed link, or no login at all | **No** |

This is verified in the code today:
- GMS `guest` is a real first-class role; guests log in through GMS's own
  email/OTP flow (`guest.routes.ts` → `requireAuth`, but the credential is GMS's,
  not the IdP's).
- DMS `GET /letters/verify` is mounted **before** auth and is explicitly public
  (QR verification of a printed letter needs no account).

**Rule of thumb:** SSO is opt-in per *surface*, never global. If an endpoint is
for external users or the public, it does **not** go through the IdP — it keeps
whatever it does today. Nothing I built changes those paths.

---

## 2. Does OIDC lock us into Node? **No — this is the important one.**

OpenID Connect / OAuth 2.0 is a **wire protocol over plain HTTP**, not a library.
The IdP publishes a standards discovery document
(`/.well-known/openid-configuration`) and a JWKS. **Any** language that can make
an HTTPS call and verify an RS256 JWT is a first-class client:

| Stack | Mature OIDC client |
|-------|--------------------|
| PHP | `jumbojett/OpenID-Connect-PHP`, `league/oauth2-client` |
| Plain JS / SPA | `oidc-client-ts` (browser), or the auth-code flow by hand (~40 lines) |
| Node | `openid-client`, or hand-rolled (DMS does this today) |
| .NET / Java / Python / Go | first-party OIDC middleware in every framework |

So the CTO answer is the opposite of the fear: **choosing self-hosted OIDC is
precisely what keeps legacy PHP and plain-JS apps integratable.** A proprietary
vendor SDK would be the thing that locks you in. Our IdP (`oidc-provider`, Panva)
is OpenID-certified-grade and speaks the standard every stack already supports.

If any old system genuinely *cannot* be made an OIDC client (can't add a login
redirect, can't verify a JWT), it still integrates via the **token bridge**
pattern (§4B) — which is exactly how we onboarded GMS without touching its code.

---

## 3. Gateway / routing: what the IdP is, and what it is deliberately **not**

The IdP plays three roles. Only the first is mandatory:

1. **Authorization server (mandatory).** Issues identity. `/authorize`, `/token`,
   `/jwks`, `/userinfo`, `/session/end`, plus the login/consent UI. This is the
   SSO backbone (a persistent session cookie = sign in once, reach every app).
2. **SSO portal (a real frontend, not just an API).** `/portal` is a launcher that
   greets the user and opens each app, reusing the session. The IdP is **not**
   headless — it ships EJS login/consent/portal pages.
3. **Token relay for no-touch apps (optional, per app).** `/gms/api/*` proxies to
   GMS's backend injecting the bridged `Authorization` header, so a same-origin
   GMS SPA works with zero GMS changes.

What the IdP is **NOT**, on purpose:

- **Not a mandatory reverse-proxy in front of every app.** Apps stay independently
  reachable on their own hosts. This is *why* public routes and external users
  "just work" — there's no front door forcing auth on `/letters/verify` or GMS
  guest login.
- **Not a micro-frontend shell that embeds other apps' UIs.** Each app keeps its
  own frontend (DMS Next.js :3000, GMS Next.js :5001). The IdP portal *links* to
  them; it does not host them.

### Why not a shell / full gateway?

A single shell that proxies every app under one domain sounds tidy but fights
three of your constraints:
- **Public routes** would have to be carefully carved out of a front door that
  otherwise wants to authenticate everything — easy to get wrong, easy to leak.
- **Legacy PHP / plain-JS** apps don't slot into a Next.js micro-frontend host or
  a base-path rewrite cleanly; a proxy shell adds fragile URL rewriting per app.
- **Deployment coupling** — one shell in front of everything becomes a single
  choke point you must scale and version in lockstep with each app.

The chosen model — **portal + per-app frontends + standard OIDC redirects** — is
how Google (accounts.google.com), Microsoft, Okta-fronted estates, etc. actually
work: a central login/portal, each app on its own origin, SSO via redirect. It is
lower-risk, legacy-friendly, and public-route-friendly.

**Routing in production** is therefore ordinary infrastructure, not app logic:
subdomains behind your existing reverse proxy / load balancer
(`idp.examplecorp.com`, `dms.examplecorp.com`, `gms.examplecorp.com`), each with TLS.
The load balancer does host-based routing; the IdP does identity. They are
separate concerns and stay that way.

> Optional future: if you later want a single-domain experience, add a thin
> reverse-proxy in front (the `/gms/api` relay is the first brick). It stays
> **additive** — apps remain directly reachable — so it never becomes the choke
> point a mandatory shell would.

---

## 4. The two integration patterns (choose per app)

### A. OIDC client — *preferred, any language*
Use when you can add a "Sign in with Example Corp" redirect to the app (you control
its login, even if it's PHP or plain JS).

```
app → redirect to idp /authorize → user logs in once → idp redirects back with code
    → app exchanges code at /token → gets id_token → maps identity to its own roles
```
DMS uses this today. A PHP app uses `jumbojett/OpenID-Connect-PHP` in ~15 lines.

### B. Token bridge — *no-touch, for apps you cannot modify*
Use when you must **not** change the app's auth (like GMS). After OIDC login at the
IdP, a small IdP-side adapter provisions the app's own user record and mints a
token the app already accepts.

```
idp login → bridge: provision app user + mint app-native token (app's own secret)
          → deliver to browser → app verifies it as if it issued it
```
GMS uses this: the bridge signs an HS256 token with GMS's secret and writes a
`gmsdev.users` row. **Zero GMS code changed.** A legacy PHP app whose session
mechanism you can't touch would get its own bridge adapter modeled on
`IdP/identity/src/bridge/gms.ts`.

**Decision guide:** can you add a login redirect / verify a JWT in the app? →
Pattern A. If truly not → Pattern B. Both leave external/guest/public flows alone.

---

## 5. Roles: apps keep their own; the IdP only supplies identity + groups

The IdP is intentionally **role-agnostic**. Internal role systems stay embedded in
each app (that's fine — it's not something to extract):
- IdP issues: `sub`, `email`, `email_verified`, name, and an `ad_groups[]` claim.
- **DMS** maps groups → its roles via the `idp_role_mappings` table.
- **GMS** bridge maps groups → its roles via `idp_gms_role_mappings`.
- External/guest roles (GMS `guest`, DMS external signer) are **never** assigned by
  the IdP — they come from the app's own external flow.

So "internal and external roles are embedded in the apps" is not a problem to
solve — it's the design. The IdP authenticates *who you are*; each app decides
*what you may do*, exactly as it does now.

---

## 6. Component & topology map

```
                         External / public plane (NO IdP)
   guest ── GMS native login (email/OTP) ─────────────▶ GMS
   signer ─ DMS signed document link ─────────────────▶ DMS
   public ─ DMS /letters/verify (QR, no auth) ────────▶ DMS

                         Internal plane (SSO)
   staff ─▶ idp.examplecorp.com  (oidc-provider + portal)
              │  OIDC (RS256/JWKS)         token bridge (app-native)
              ├────────────▶ DMS/EDAMS        ├────────────▶ GMS (staff)
              └────────────▶ future OIDC app  └────────────▶ future no-touch app
   identity source: Active Directory (LDAP) → local Postgres fallback
   store: Postgres `idp` (separate DB; no app shares a DB)
```

Ports / DBs (all isolated): DMS 4000·3000·`DMS` · GMS 5000·5001·`gmsdev` ·
IdP 4100·`idp`.

---

## 7. Honest status & known seams (verified in a real browser)

Verified end-to-end with headless Chromium (`IdP/identity/test-scripts/browser-clickthrough.mjs`, 10/10 checks) + live API tests:
- **IdP OIDC end-to-end** — login → consent (auto-granted for first-party) → token; id_token
  carries `sub`/`email`/`email_verified`/`ad_groups`/`nonce`.
- **DMS full SSO** — "Sign in with Example Corp SSO" → IdP → **DMS dashboard**; user
  JIT-provisioned `SYSTEM_ADMIN` (from `EDAMS_Admins`), `external_sub` persisted.
- **Portal (Model A)** — authenticated + personalized ("Welcome, System Administrator"),
  entitled tiles only, reached with **no second password** (SSO reused).
- **GMS staff SSO** — portal "Open GMS" → bridge → same-origin gateway → lands on the
  **authenticated GMS `/admin` console** ("Active role: Super Admin"), API calls succeed
  same-origin. **Zero GMS code changes.**

Design decisions now implemented:
- **Same-origin gateway for GMS** (§3) is built: a reverse proxy on `gms.localtest.me:4200`
  serves the GMS SPA + proxies its API on one origin, so the bridged session seeds the SPA's
  localStorage and API calls avoid CORS. This closes the earlier cross-origin handoff gap.
  It stays **additive** — GMS is still directly reachable on :5001, and its guest/staff-login
  flows are untouched.
- **Auto-consent for first-party clients** makes app-hopping seamless (no consent screen).
- **Root `/` → `/portal`** so the IdP has a friendly landing.

Known seams / later work:
- **Protocol-universal but only Node/Next exercised.** PHP/plain-JS integrate by the standard
  (see the integration guide); pilot the first legacy app end to end.
- **No micro-frontend shell** — by design (§3). The gateway fronts GMS specifically because we
  can't touch it; OIDC apps keep their own frontends + a login redirect.
- **GMS admin data loads same-origin (CORS resolved).** The staff SPA's API + socket are
  pointed at the gateway origin via a GMS-frontend `.env.local` (local override, not auth code);
  direct `:5001` access is unaffected. Verified: no cross-origin `:5000` calls, `/offices` 200,
  operational queue/alerts/activity panels load. One endpoint the SPA calls,
  `/operations/integration-health`, returns **404 on the GMS backend itself** (identical direct
  and via gateway) — a GMS-side missing route, out of scope for the SSO layer.
- **Scale/hardening:** Redis for multi-instance sessions, and productionizing the one-time handoff
  code + gateway session store (currently in-memory). **Done since 2026-07-12:** JWKS rotate/retire
  now take effect live (`jwks.ts`'s `reloadProviderKeys()`) — no restart needed, and no longer
  listed here as outstanding; MFA brute-force lockout is implemented for every account regardless
  of whether primary auth was AD or local-store (the TOTP verification step itself is what's
  rate-limited, not tied to the auth source).

See `SSO-INTEGRATION-GUIDE.md` (add an app) and `SSO-OPERATIONS.md` (run/deploy).
