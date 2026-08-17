/**
 * oidc-provider (Panva) instance — the spec-compliant OAuth2/OIDC engine that
 * replaces the hand-rolled scaffold flow.
 *
 * Gives us for free: authorization-code + PKCE (required), refresh tokens with
 * rotation, /userinfo, introspection, revocation, RP-initiated logout, JWKS, and
 * — critically — a persistent SSO session cookie so one login covers every app.
 *
 * Persistence: single-table Postgres adapter (incl. Session). Signing keys are
 * loaded from Postgres (stable across restarts). Interactions render our own
 * login/consent views (see interactions/).
 */

import Provider, { type Configuration } from 'oidc-provider';
import { AD_GROUPS_CLAIM, IDP_CONFIG } from '../config.js';
import { EDAMS_ROLES_CLAIM, GMS_ROLES_CLAIM } from '../auth/client-role-claims.js';
import { postgresAdapterFactory } from '../adapters/postgres.js';
import { findAccount } from '../auth/account.js';
import { loadClients, seedClients } from './clients.js';
import { loadSigningJwks } from '../jwks.js';

export async function buildProvider(): Promise<Provider> {
  await seedClients();
  const clients = await loadClients();
  const jwks = await loadSigningJwks();

  const configuration: Configuration = {
    adapter: postgresAdapterFactory,
    clients,
    jwks: { keys: jwks } as Configuration['jwks'],

    // Claims surfaced per scope. ad_groups + client-scoped roles ride on
    // `profile` so they reach relying parties that request `openid profile email`.
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: [
        'given_name',
        'family_name',
        'name',
        AD_GROUPS_CLAIM,
        GMS_ROLES_CLAIM,
        EDAMS_ROLES_CLAIM,
      ],
    },

    // DMS reads claims straight from the id_token (it does not call /userinfo),
    // so place all requested claims into the id_token rather than only userinfo.
    conformIdTokenClaims: false,

    findAccount,

    features: {
      devInteractions: { enabled: false }, // we ship real views
      introspection: { enabled: true },
      revocation: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        // Auto-confirm the end-session prompt: the portal's "Sign out" already
        // expresses intent (and carries id_token_hint), so don't interpose
        // oidc-provider's bare "do you want to sign out?" form — submit it with
        // logout=yes on load and end the full SSO session in one click.
        logoutSource: async (ctx, form) => {
          ctx.type = 'html';
          ctx.body = `<!DOCTYPE html><html><head><title>Signing out…</title></head>
<body onload="document.forms['op.logoutForm'].submit()">
  ${form.replace('</form>', '<input type="hidden" name="logout" value="yes"/></form>')}
  <noscript><p>Confirm sign-out:</p><button type="submit" form="op.logoutForm" name="logout" value="yes">Sign out</button></noscript>
</body></html>`;
        },
      },
      userinfo: { enabled: true },
    },

    // Require PKCE for public clients (OAuth 2.1). First-party confidential
    // clients (DMS/GMS, which authenticate with a client secret) may omit it,
    // so DMS's existing non-PKCE authorize keeps working with no DMS change.
    // NOTE: every client currently registered in idp_clients is seeded with
    // token_endpoint_auth_method: 'client_secret_post' (oidc/clients.ts) — no
    // public ('none') client exists yet, so this condition is never true today
    // and PKCE isn't actually enforced by the provider config for anyone. It's
    // real, correct policy for the day a public/SPA client is registered; it
    // just isn't doing anything yet. (Recommendation: add PKCE to DMS later
    // and flip this to always-true.)
    pkce: { required: (_ctx, client) => client.tokenEndpointAuthMethod === 'none' },

    // DMS's OIDC client calls `${AUTH_ISSUER}/authorize`; align the route name
    // (oidc-provider defaults to /auth).
    routes: { authorization: '/authorize' },

    ttl: {
      AccessToken: IDP_CONFIG.ttl.accessToken,
      IdToken: IDP_CONFIG.ttl.idToken,
      RefreshToken: IDP_CONFIG.ttl.refreshToken,
      Session: IDP_CONFIG.ttl.session,
      Interaction: IDP_CONFIG.ttl.interaction,
      Grant: IDP_CONFIG.ttl.grant,
    },

    cookies: {
      keys: IDP_CONFIG.cookieKeys,
      long: { signed: true, httpOnly: true, sameSite: 'lax' },
      short: { signed: true, httpOnly: true, sameSite: 'lax' },
    },

    // Rotating refresh tokens with reuse detection is on by default for public
    // and code clients; keep the default issueRefreshToken behavior but ensure
    // offline_access isn't required to get a refresh token for our first-party apps.
    issueRefreshToken: async (_ctx, client, code) => {
      return client.grantTypeAllowed('refresh_token') && (code.scopes as Set<string>).has('openid');
    },

    // Route interactions to our own login/consent UI.
    //
    // Must carry IDP_CONFIG.publicBasePath: oidc-provider returns this value to
    // the browser as a redirect Location, and it does NOT derive a path prefix
    // from the issuer for it. Without the prefix, a login under
    // https://portal.examplecorp.com/sso sends the browser to
    // /interaction/{uid} — no nginx rule matches that, so the whole login flow
    // dead-ends on a 404 from the reverse proxy. Empty string when root-hosted (dev).
    interactions: {
      url(_ctx, interaction) {
        return `${IDP_CONFIG.publicBasePath}/interaction/${interaction.uid}`;
      },
    },

    // Every registered client today is confidential (client_secret_post,
    // clients.ts) rather than a public/PKCE browser client, so this has been
    // dormant — but `() => true` would allow ANY website to cross-origin
    // fetch /token or /userinfo the moment a public client is ever
    // registered, instead of only that client's own registered origins.
    // Scope it to the requesting client's redirect_uris the way the CORS
    // model is meant to work: an origin is allowed only if it matches one of
    // that specific client's own registered redirect URIs.
    clientBasedCORS: (_ctx, origin, client) => {
      return (client.redirectUris ?? []).some((uri: string) => {
        try {
          return new URL(uri).origin === origin;
        } catch {
          return false;
        }
      });
    },
  };

  const provider = new Provider(IDP_CONFIG.issuer, configuration);

  // Trust the reverse proxy (Phase 8 gateway / TLS terminator) for correct
  // protocol + host on issued URLs and secure cookies.
  provider.proxy = true;

  return provider;
}
