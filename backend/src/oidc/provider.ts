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
import { hasLogoutIntent, LOGOUT_INTENT_COOKIE } from '../auth/logout-intent.js';
import { AD_GROUPS_CLAIM, IDP_CONFIG } from '../config.js';
import { EDAMS_ROLES_CLAIM, GMS_ROLES_CLAIM } from '../auth/client-role-claims.js';
import { accountHasAppAccess, APP_ROLES_CLAIM } from '../auth/app-roles.js';
import { postgresAdapterFactory } from '../adapters/postgres.js';
import { findAccount } from '../auth/account.js';
import { seedClients } from './clients.js';
import { seedClientRoles } from './client-roles-config.js';
import { loadSigningJwks } from '../jwks.js';
import { pool } from '../db/pool.js';
import { revokeAllSessions } from '../auth/revoke.js';
import { logger } from '../logging/logger.js';
import { getNumber } from '../settings/store.js';
import { pinEndSessionOrigin } from './end-session-origin.js';

export async function buildProvider(): Promise<Provider> {
  await seedClients();
  await seedClientRoles();
  const jwks = await loadSigningJwks();

  const configuration: Configuration = {
    adapter: postgresAdapterFactory,
    // No static `clients` list: oidc-provider reads each client through the adapter's `Client` model (adapters/postgres.ts ->
    // oidc/clients.ts findClientMetadata) on every request, so the console's Clients page takes effect without a restart.
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
      ],

      /**
       * P1-2: the three custom claims used to sit inside `profile`, alongside
       * name/given_name/family_name. Combined with conformIdTokenClaims: false
       * that put ALL of them in EVERY client's id_token — the gms client received
       * the user's DMS roles, the edams client received their GMS roles, and the
       * portal received both. Another system's internal authorization model
       * crossing a trust boundary for no reason, and impossible to scope because
       * a client that legitimately needs `profile` could not decline the rest.
       *
       * Each now has its own scope. oidc-provider turns every key of this map
       * into a requestable scope automatically (collectScopes() in
       * lib/helpers/configuration.js), and only emits the claim when that scope
       * was both requested and granted, so the per-client `scope` allowlist in
       * oidc/clients.ts is what actually enforces the separation.
       *
       * ad_groups is granted to all three relying parties deliberately — the
       * portal builds its app tiles from the group list, the GMS bridge maps
       * groups to GMS roles, and DMS uses them for its idp_role_mappings
       * fallback. What this buys is role-claim separation between RPs, not
       * hiding the directory from all of them; claiming otherwise would be
       * overselling it.
       */
      ad_groups: [AD_GROUPS_CLAIM],
      gms_roles: [GMS_ROLES_CLAIM],
      edams_roles: [EDAMS_ROLES_CLAIM],
      // The roles the person holds in the application that asks, for applications managed from the console (auth/app-roles.ts).
      // Same separation as the two above: only a client whose scope allowlist includes `app_roles` gets it, and the value is
      // always that client's own roles.
      app_roles: [APP_ROLES_CLAIM],
    },

    // DMS reads claims straight from the id_token (it does not call /userinfo),
    // so place all requested claims into the id_token rather than only userinfo.
    conformIdTokenClaims: false,

    findAccount,

    /**
     * oidc-provider's default, with one addition: an application managed from the console (auth/app-roles.ts) is checked at EVERY
     * authorization, not only the first. When the person no longer holds a role in it there is no usable grant, so the request
     * goes to the consent step (interactions/router.ts), which refuses it with access_denied. Without this a person whose access was
     * removed would keep getting silent sign-ins for as long as their old grant lived.
     */
    async loadExistingGrant(ctx) {
      const clientId = ctx.oidc.client?.clientId;
      const accountId = ctx.oidc.session?.accountId;
      if (clientId && accountId && !(await accountHasAppAccess(accountId, clientId))) return undefined;
      const grantId = ctx.oidc.result?.consent?.grantId || (clientId ? ctx.oidc.session?.grantIdFor(clientId) : undefined);
      return grantId ? ctx.oidc.provider.Grant.find(grantId) : undefined;
    },

    features: {
      devInteractions: { enabled: false }, // we ship real views
      introspection: { enabled: true },
      revocation: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        /**
         * P1-5. This used to auto-submit unconditionally, on load, for EVERY
         * RP-initiated logout. oidc-provider's confirmation form exists
         * specifically to stop logout CSRF; auto-submitting it meant any
         * third-party page a signed-in user visited could end their entire SSO
         * session — portal, DMS and GMS at once — with a hidden
         * `<iframe src="…/session/end?client_id=portal">`. The justification in
         * the old comment ("the portal's Sign out already expresses intent") was
         * true of the portal's own button and of nothing else, yet the handler
         * applied to all callers.
         *
         * Now the auto-submit is conditional on an intent cookie that only our
         * own POST /portal/logout sets (auth/logout-intent.ts). An attacker's
         * page cannot set a cookie on this origin, so a cross-site request lands
         * on the real confirmation form and the session survives until a human
         * clicks the button.
         *
         * The cookie is deliberately NOT cleared here. The portal frontend signs
         * out with fetch() and then navigates the browser to the same
         * /session/end URL (see frontend/app/portal/page.tsx), so this handler
         * runs twice for one sign-out; clearing on the first pass would leave the
         * real navigation without a cookie and show the user a confirmation
         * prompt they already answered. A 60-second max-age bounds it instead,
         * and re-use inside that window is by definition the same user's own
         * sign-out.
         */
        logoutSource: async (ctx, form) => {
          const intent = hasLogoutIntent(ctx.cookies.get(LOGOUT_INTENT_COOKIE, { signed: false }));
          ctx.type = 'html';
          ctx.set('cache-control', 'no-store');
          if (intent) {
            // The nonce set by http/csp.ts (P2-8). `onload` is an inline event
            // HANDLER, which a nonce cannot authorise — only `<script>` elements
            // can carry one — so the auto-submit moved into a real nonced script
            // tag. Same behaviour, and it no longer needs 'unsafe-inline'.
            const nonce = String((ctx.res as unknown as { locals?: { cspNonce?: string } }).locals?.cspNonce ?? '');
            ctx.body = `<!DOCTYPE html><html><head><title>Signing out…</title></head>
<body>
  ${form.replace('</form>', '<input type="hidden" name="logout" value="yes"/></form>')}
  <p>Signing you out…</p>
  <!-- Always present, not inside <noscript>. If the nonced script below is
       blocked (no nonce available, or a browser/extension policy), a visible
       button is the difference between a working sign-out and a dead-end page.
       The script hides it, so nobody normally sees it. -->
  <button id="op-logout-fallback" type="submit" form="op.logoutForm" name="logout" value="yes">Sign out</button>
  <script nonce="${nonce}">
    document.getElementById('op-logout-fallback').style.display = 'none';
    document.forms['op.logoutForm'].submit();
  </script>
</body></html>`;
            return;
          }
          // No auto-submit, no onload, no script at all — a plain button the user
          // has to press. `logout=yes` rides on the button itself, so pressing
          // "Stay signed in" (i.e. navigating away) leaves the session intact.
          ctx.body = `<!DOCTYPE html><html><head><title>Sign out?</title></head>
<body>
  <h1>Sign out of Example Corp SSO?</h1>
  <p>This ends your session for every connected application.</p>
  ${form}
  <button type="submit" form="op.logoutForm" name="logout" value="yes">Sign out</button>
</body></html>`;
        },
      },
      userinfo: { enabled: true },
    },

    /**
     * PKCE required for EVERY client (P2-9 items 24 and 4 of P2-5).
     *
     * This used to be `client.tokenEndpointAuthMethod === 'none'`, and the old
     * comment was honest that no such client existed — every seeded client uses
     * client_secret_post — so PKCE was enforced for nobody. Correct policy, zero
     * effect, which is the worst kind: it reads as a control in place.
     *
     * All three relying parties now send an S256 code_challenge: the portal and
     * the GMS bridge always did (portal/router.ts, bridge/router.ts) and DMS's
     * /auth/oidc/authorize was given one (DMS auth.routes.ts, migration
     * 20260822000005). So this can finally be unconditional.
     *
     * If a fourth system is ever registered, it MUST send a code_challenge or its
     * authorize request will be rejected — which is the intended behaviour, and
     * is why this is stated here rather than left implicit.
     */
    pkce: { required: () => true },

    // DMS's OIDC client calls `${AUTH_ISSUER}/authorize`; align the route name
    // (oidc-provider defaults to /auth).
    routes: { authorization: '/authorize' },

    // Token and session lifetimes are platform settings (settings/registry.ts, defaults from the TTL_* environment values). oidc-provider
    // accepts a plain synchronous function and calls it for every new artifact, so a change in the console applies to the very next
    // token without a restart. (It must be a regular function returning a number, never async.)
    ttl: {
      AccessToken: () => getNumber('ttl.accessTokenSeconds'),
      IdToken: () => getNumber('ttl.idTokenSeconds'),
      RefreshToken: () => getNumber('ttl.refreshTokenHours') * 3600,
      Session: () => getNumber('ttl.ssoSessionHours') * 3600,
      Interaction: IDP_CONFIG.ttl.interaction,
      // A grant lives as long as the sign-in it came from.
      Grant: () => getNumber('ttl.ssoSessionHours') * 3600,
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
    // /interaction/{uid} — no Apache rule matches that, so the whole login flow
    // dead-ends on an Apache 404. Empty string when root-hosted (dev).
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
  /**
   * P2-9 item 4. oidc-provider's `proxy` flag makes it trust X-Forwarded-* at
   * UNBOUNDED depth, while the Express app in front of it deliberately uses
   * `trust proxy = IDP_CONFIG.trustProxyHops` (default 1) after a documented
   * IP-spoofing fix. Two different answers to "how many proxies are in front of
   * us" in one process is how a spoofed X-Forwarded-For gets believed by one half
   * and rejected by the other.
   *
   * Koa exposes the same bounded notion as `proxyIpCount`, so set both from the
   * single source of truth. Behind the single Apache edge (hops = 1) this is
   * identical to the old behaviour; it stops being identical exactly when someone
   * adds a second proxy or an attacker adds a header hop, which is the point.
   */
  provider.proxy = true;
  (provider.app as unknown as { proxyIpCount: number }).proxyIpCount = IDP_CONFIG.trustProxyHops;

  // The sign-out pages are built for the issuer's own address whatever Host the last proxy reports (end-session-origin.ts).
  provider.use(pinEndSessionOrigin(IDP_CONFIG.issuer));

  // Single logout: when a relying party ends the SSO session (RP-initiated /session/end), the portal session -- the
  // credential of the admin console -- and every other live session of that person must end too. Until now only the
  // SSO cookie died and the portal session lived on for its full 14 days.
  provider.on('end_session.success', (ctx: { oidc?: { session?: { accountId?: string } } }) => {
    const accountId = ctx.oidc?.session?.accountId;
    if (!accountId) return;
    void (async () => {
      const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [accountId]);
      await revokeAllSessions(accountId, rows[0]?.email ?? '');
    })().catch((err) => logger.error({ err, accountId }, '[idp:logout] session revoke after end_session failed'));
  });

  return provider;
}
