# Example Corp SSO — Architecture

This document answers the "how does this actually fit together" questions:
public vs. authenticated access, internal vs. external users, legacy
(PHP / plain-JS) integration, whether a gateway/shell or microservices are
needed, and where the seams are.

## Contents

1. [The one idea that makes this simple: two identity planes, not two systems](#1-the-one-idea-that-makes-this-simple-two-identity-planes-not-two-systems)
2. [Does OIDC lock you into one language?](#2-does-oidc-lock-you-into-one-language)
3. [What the identity provider is, and what it deliberately is not](#3-what-the-identity-provider-is-and-what-it-deliberately-is-not)
4. [The two integration patterns](#4-the-two-integration-patterns)
5. [Roles: apps keep their own; the IdP only supplies identity and groups](#5-roles-apps-keep-their-own-the-idp-only-supplies-identity-and-groups)
6. [Component and topology map](#6-component-and-topology-map)
7. [Design decisions and known seams](#7-design-decisions-and-known-seams)

---

## 1. The one idea that makes this simple: two identity planes, not two systems

This is **not** a microservices split, and it does **not** force every
request through a front door. Each application stays exactly what it is
today — a self-contained system with its own database. One shared
service is added — the identity provider (IdP) — and it's applied
**selectively**.

Every application already serves two kinds of caller. Keep them separate
at the *authentication* level, not the *deployment* level:

| Plane | Who | How they authenticate | Touches the IdP? |
|---|---|---|---|
| **Internal** | Staff / employees | SSO via the IdP (OIDC, or a token bridge for a legacy app) | Yes |
| **External** | Guests, external document signers, anyone verifying a public link | Each app's own native or public flow — email+OTP, a signed link, or no login at all | **No** |

**Rule of thumb:** SSO is opt-in per *surface*, never global. If an
endpoint is for external users or the general public, it does **not** go
through the IdP — it keeps whatever it does today. A guest check-in flow
or a public document-verification page needs no account and should never
be routed through the identity provider.

---

## 2. Does OIDC lock you into one language?

OpenID Connect / OAuth 2.0 is a **wire protocol over plain HTTP**, not a
library. The IdP publishes a standard discovery document
(`/.well-known/openid-configuration`) and a JWKS. **Any** language that
can make an HTTPS call and verify an RS256 JWT is a first-class client:

| Stack | Mature OIDC client |
|---|---|
| PHP | `jumbojett/OpenID-Connect-PHP`, `league/oauth2-client` |
| Plain JS / SPA | `oidc-client-ts` (browser), or the auth-code flow by hand (~40 lines) |
| Node | `openid-client`, or a hand-rolled flow |
| .NET / Java / Python / Go | first-party OIDC middleware in every mainstream framework |

Choosing a self-hosted, standards-based OIDC provider is precisely what
keeps a legacy PHP app or a plain-JS app integratable — a proprietary
vendor SDK is the thing that would actually lock you in. A spec-compliant
provider speaks the same protocol every stack already supports.

If an existing system genuinely *cannot* be made an OIDC client (it can't
add a login redirect, can't verify a JWT), it can still integrate via the
**token bridge** pattern ([§4](#4-the-two-integration-patterns)) with zero
changes to its own code.

---

## 3. What the identity provider is, and what it deliberately is not

The IdP plays three roles. Only the first is mandatory:

1. **Authorization server (mandatory).** Issues identity —
   `/authorize`, `/token`, `/jwks`, `/userinfo`, `/session/end`, plus the
   login/consent UI. This is the SSO backbone: sign in once, reach every
   integrated app for the lifetime of that session.
2. **A real portal frontend, not just an API.** A launcher page greets
   the signed-in user and opens each app, reusing the existing session.
   The IdP is not headless — it has real login, consent, portal, and
   admin pages, served by its own frontend.
3. **A same-origin gateway for no-touch apps (optional, per app).** For
   an app that cannot be modified at all, a small reverse proxy serves
   that app's frontend and proxies its API on one origin, so a
   bridged session survives normal cookie same-site rules with zero
   changes to the target app.

What the IdP is **not**, on purpose:

- **Not a mandatory reverse proxy in front of every app.** Each app stays
  independently reachable on its own address. This is *why* public routes
  and external users keep working unmodified — there's no front door
  forcing authentication onto a route that's meant to stay open.
- **Not a micro-frontend shell that embeds other apps' UIs.** Each app
  keeps its own frontend. The portal *links* to them; it does not host
  them.

### Why not a single shell in front of everything?

A single shell proxying every app under one domain sounds tidy but fights
three real constraints: public routes would have to be carefully carved
out of a front door that otherwise wants to authenticate everything
(easy to get wrong, easy to leak); legacy apps in older stacks don't slot
cleanly into a micro-frontend host or a base-path rewrite; and one shell
in front of everything becomes a single choke point that has to scale and
version in lockstep with every app behind it.

The model actually used — **a portal, each app on its own frontend,
standard OIDC redirects between them** — is how most large identity
platforms are organized: a central login/portal, each app on its own
origin, SSO via redirect. It's lower-risk and friendlier to both legacy
apps and public routes than a universal front-door shell.

**Routing in production is ordinary infrastructure, not application
logic** — the reverse proxy routes, the IdP does identity, and the two
stay separate concerns. Path-based routing on one shared reverse-proxy
host (`/sso`, `/app-one`, `/app-two`, ...) is a reasonable choice when you
want one certificate and one vhost rather than one per system; the cost
is that each frontend must be *built* knowing its own base path, since
that's baked into the bundle at build time — changing it means a
rebuild, not a restart.

---

## 4. The two integration patterns

### A. OIDC client — preferred, any language

Use when you can add a "Sign in with SSO" redirect to the app — you
control its login, even if it's written in an older stack.

```
app → redirect to IdP /authorize → user logs in once → IdP redirects back with a code
    → app exchanges the code at /token → gets an id_token → maps identity to its own roles
```

A PHP app can implement this in about fifteen lines using an existing
OIDC client library.

### B. Token bridge — no-touch, for apps you cannot modify

Use when you must **not** change the app's own authentication. After
login at the IdP, a small IdP-side adapter provisions the app's own user
record and mints a token the app already accepts natively — its own JWT
format, a session row, a signed cookie, whatever it already trusts.

```
IdP login → bridge: provision the app's own user + mint the app's native token
          → deliver to the browser → the app verifies it exactly as if it issued it itself
```

**Zero code changes to the target app.** A legacy application whose
session mechanism can't be touched gets its own bridge adapter, modeled
on the same shape as any other bridge integration.

**Decision guide:** can you add a login redirect / verify a JWT in the
app? Use Pattern A. If genuinely not, use Pattern B. Both leave
external/guest/public flows alone entirely.

---

## 5. Roles: apps keep their own; the IdP only supplies identity and groups

The IdP is intentionally **role-agnostic**. Each integrated app's own
role system stays embedded in that app — that's the design, not a gap to
close later:

- The IdP issues `sub`, `email`, `email_verified`, name fields, and a
  group-membership claim.
- Each integrated app maps groups to its own roles via its own
  group-to-role mapping table (or asks the IdP to resolve a
  coarse, app-specific `roles` claim for it — see the integration guide).
- External/guest roles are **never** assigned by the IdP — they come
  entirely from the app's own external flow.

The IdP authenticates *who you are*; each app decides *what you may do*,
exactly as it would without SSO in the picture at all.

---

## 6. Component and topology map

```
                         External / public plane (NO IdP)
   guest ── an app's native login (email/OTP) ───────▶ that app
   signer ─ a signed document link ───────────────────▶ that app
   public ─ a public verification page (no auth) ─────▶ that app

                         Internal plane (SSO)
   staff ─▶ the identity provider  (OIDC provider + portal)
              │  OIDC (RS256/JWKS)         token bridge (app-native)
              ├────────────▶ an OIDC-client app   ├────────────▶ a no-touch legacy app
              └────────────▶ future OIDC app      └────────────▶ future no-touch app
   identity source: your directory service (e.g. LDAP/AD) → a local user-store fallback
   store: the IdP's own database (separate from every relying party; no app shares a database)
```

Every system's development port is also its production port; only the
environment name, host binding, database name/password, and public URL
differ between the two. Each integrated system owns its own database —
no system shares a database with another, including the identity
provider itself.

---

## 7. Design decisions and known seams

A few decisions worth calling out explicitly because they shape how a new
integration should be designed:

- **The same-origin gateway is additive, never exclusive.** A no-touch
  legacy app integrated via the token bridge stays directly reachable on
  its own address too — the gateway is one more door in, not the only
  one, and the app's own native login (staff or guest) is left
  completely untouched.
- **Auto-consent for first-party, trusted clients** makes moving between
  integrated apps seamless — no repeated consent screen for an app the
  organization itself owns and operates.
- **The identity provider is protocol-universal but easiest to prove out
  with a Node/Next.js client first** — a non-Node or legacy stack
  integrates identically by protocol, but pilot the first such
  integration end to end rather than assuming it "should just work"
  without ever exercising it.
- **No micro-frontend shell, by design** ([§3](#3-what-the-identity-provider-is-and-what-it-deliberately-is-not)).
  The gateway pattern exists specifically for apps that can't be touched;
  an app you can modify keeps its own frontend and simply adds a login
  redirect.
- **Scale considerations worth planning for early**: session and
  one-time-handoff-code storage should live in a shared store (not
  in-process memory) the moment more than one instance of the IdP backend
  runs concurrently, and JWKS rotation should take effect live, without
  requiring a restart, so a key rotation never has an availability cost.

See `SSO-INTEGRATION-GUIDE.md` for adding a new application, and
`SSO-OPERATIONS.md` for running and deploying the identity provider
itself.
