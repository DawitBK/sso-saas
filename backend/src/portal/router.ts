/**
 * SSO app-launcher portal — Model A: the authenticated home page staff land on.
 *
 * The portal is itself an OIDC relying party of this IdP, so it reuses the shared
 * SSO session to learn who is signed in (no extra prompt if already logged in
 * elsewhere), greets them, and shows only the apps they're entitled to
 * (`idp_app_entitlements`). Each tile launches that app's SSO flow.
 */

import { newPasswordProblem } from '../auth/password-policy.js';
import { createHash } from 'node:crypto';
import express, { Router, type Request, type Response, type NextFunction } from 'express';
import { reuseOrIssueCsrf } from '../http/csrf-token.js';
import { createLimiter } from '../infrastructure/rateLimiter.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import crypto from 'node:crypto';
import { AD_GROUPS_CLAIM, IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { getPortalSession, putPortalSession, dropPortalSession, type PortalSession } from './session.js';
import { catalog, adminTile, entitled } from './catalog.js';
import { setWebSession, takeWebSession, getWebSession, dropWebSession } from '../db/web-sessions.js';
import { revokeGmsSessionsByEmail } from '../bridge/gms.js';
import { notifyAppLogouts, notifyDmsLogout } from '../auth/logout-notify.js';
import { revokeAllSessions } from '../auth/revoke.js';
import {
  checkMfaLockout, getTotpState, enableTotp, disableTotp, recordMfaAttempt,
  canSelfChangePassword, verifyCurrentPassword, completePasswordChange,
} from '../auth/local-users.js';
import { generateTotpSecret, verifyTotp, otpauthUri } from '../auth/totp.js';
import { recoveryCodesRemaining, replaceRecoveryCodes } from '../auth/recovery-codes.js';
import { hashPassword } from '../auth/password.js';
import { writeAudit } from '../admin/audit.js';
import { createFlowBinding, flowBindingMatches, flowBindingCookieOptions } from '../auth/flow-binding.js';
import { setLogoutIntent } from '../auth/logout-intent.js';

const CLIENT_ID = 'portal';
const ISS = IDP_CONFIG.issuer.replace(/\/$/, '');
const INTERNAL = IDP_CONFIG.internalUrl.replace(/\/$/, '');
const REDIRECT_URI = `${ISS}/portal/callback`;
const JWKS = createRemoteJWKSet(new URL(`${INTERNAL}/jwks`));
const clientSecret = IDP_CONFIG.clientSeed.find((c) => c.client_id === CLIENT_ID)?.client_secret ?? '';

/**
 * `bindingHash` is the SHA-256 of a token handed to the browser as an httpOnly
 * cookie at /portal/login — see auth/flow-binding.ts for why a bare `state` is
 * not enough. It is required, not optional: a pending row without it can only
 * have been written by a build that predates the binding, and is refused.
 */
interface Pending { verifier: string; nonce: string; bindingHash: string }
const PENDING_TTL_MS = 10 * 60_000;
/** Scoped to the callback path only, so it is never sent to any other route. */
const PORTAL_BIND_COOKIE = 'idp_portal_bind';
const PORTAL_BIND_PATH = `${IDP_CONFIG.publicBasePath}/portal/callback`;
const b64url = (b: Buffer) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/**
 * A browser can hold several same-name cookies at different paths (e.g. a stale
 * `idp_portal` scoped to /portal from before the cookie moved to path=/). Return
 * ALL values so the session lookup can try each — a dead stale cookie must never
 * shadow the live one (it caused an infinite login↔portal redirect loop).
 */
function cookieValues(req: Request, name: string): string[] {
  const h = req.headers.cookie;
  if (!h) return [];
  const out: string[] = [];
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i !== -1 && part.slice(0, i).trim() === name) out.push(decodeURIComponent(part.slice(i + 1).trim()));
  }
  return out;
}

async function sessionFromRequest(req: Request): Promise<PortalSession | undefined> {
  for (const v of cookieValues(req, 'idp_portal')) {
    const s = await getPortalSession(v);
    if (s) return s;
  }
  return undefined;
}

/** Same lookup as sessionFromRequest, but also returns which cookie value
 *  resolved — needed by the security page to flag "this device" among the
 *  user's own live sessions (see myOwnedSessions below). */
async function sessionWithKeyFromRequest(req: Request): Promise<{ session: PortalSession; key: string } | undefined> {
  for (const v of cookieValues(req, 'idp_portal')) {
    const s = await getPortalSession(v);
    if (s) return { session: s, key: v };
  }
  return undefined;
}

/** Double-submit CSRF for the portal's security forms (same scheme as admin/interactions). */
export function issueSecurityCsrf(res: Response): string {
  // Prefixed with publicBasePath, under /sso the console is served at /sso/admin, so the cookie path needs the public base path. Reused while the browser holds one (http/csrf-token.ts).
  return reuseOrIssueCsrf(res, 'idp_portal_csrf', { httpOnly: true, sameSite: 'lax', secure: IDP_CONFIG.isProd, path: `${IDP_CONFIG.publicBasePath}/portal` });
}

function validateSecurityCsrf(req: Request): boolean {
  const cookie = cookieValues(req, 'idp_portal_csrf')[0];
  const submitted = String((req.body as Record<string, unknown>)?.csrf ?? '');
  if (!cookie || !submitted || cookie.length !== submitted.length) return false;
  return crypto.timingSafeEqual(Buffer.from(cookie), Buffer.from(submitted));
}

/** Last 10 sign-in attempts (success + failure) for this user's own email — lets
 *  someone notice a sign-in they didn't make without needing to ask an admin to
 *  check /admin/logins on their behalf. */
async function recentLoginEventsFor(email: string): Promise<Array<{ success: boolean; reason: string; ip: string; created_at: string }>> {
  const { rows } = await pool.query<{ success: boolean; reason: string; ip: string; created_at: string }>(
    `SELECT success, reason, ip, created_at FROM idp_login_events WHERE email = $1 ORDER BY id DESC LIMIT 10`,
    [email.toLowerCase()],
  );
  return rows;
}

export interface OwnedSession { kind: string; key: string; createdAt: string; expiresAt: string | null; current: boolean }

/**
 * This user's own live sessions — the self-service counterpart of
 * /admin/sessions, scoped to the caller only (never another account's).
 * `current` flags the portal session whose cookie made this very request, so
 * the UI can hide the "sign out" control for the device someone is using
 * right now (killing it mid-render would just bounce them back to /login).
 */
async function myOwnedSessions(session: PortalSession, currentPortalKey: string | undefined): Promise<OwnedSession[]> {
  const [{ rows: webRows }, { rows: ssoRows }] = await Promise.all([
    pool.query<{ kind: string; key: string; created_at: string; expires_at: string }>(
      `SELECT kind, key, created_at, expires_at FROM idp_web_sessions
       WHERE ((kind = 'portal' AND payload->>'accountId' = $1) OR (kind = 'gateway' AND payload->>'email' = $2))
         AND expires_at > NOW()
       ORDER BY created_at DESC`,
      [session.accountId, session.email.toLowerCase()],
    ),
    pool.query<{ key: string; created_at: string; expires_at: string | null }>(
      `SELECT id AS key, created_at, expires_at FROM oidc_artifacts
       WHERE kind = 'Session' AND payload->>'accountId' = $1 AND (expires_at IS NULL OR expires_at > NOW())
       ORDER BY created_at DESC`,
      [session.accountId],
    ),
  ]);
  return [
    // The raw key IS the session cookie value. It never goes to the browser as data: an opaque sha256 id stands in for
    // it (the kill route below compares the hash), so a script injected on this origin cannot lift a live session.
    ...webRows.map((r) => ({
      kind: r.kind, key: createHash('sha256').update(r.key).digest('hex'), createdAt: r.created_at, expiresAt: r.expires_at,
      current: r.kind === 'portal' && r.key === currentPortalKey,
    })),
    ...ssoRows.map((r) => ({ kind: 'sso', key: r.key, createdAt: r.created_at, expiresAt: r.expires_at, current: false })),
  ];
}

/** Shared render for every /portal/security response — keeps the growing list of
 *  locals (MFA state, password-change eligibility, own sessions, sign-in history)
 *  consistent across the GET and every POST re-render, instead of repeating (and
 *  risking drifting) the same shape at each call site. */
async function renderSecurity(
  res: Response,
  session: PortalSession,
  currentPortalKey: string | undefined,
  opts: { pending?: { secret: string; uri: string } | null; error?: string | null; passwordError?: string | null; status?: number; newCodes?: string[] | null } = {},
): Promise<void> {
  const [totp, canChangePassword, recentLogins, mySessions, codesLeft] = await Promise.all([
    getTotpState(session.accountId),
    canSelfChangePassword(session.accountId),
    recentLoginEventsFor(session.email),
    myOwnedSessions(session, currentPortalKey),
    recoveryCodesRemaining(session.accountId),
  ]);
  // A secret the server cannot decrypt would otherwise render as a perfectly
  // healthy "two-factor is on" page while every code the user types fails
  // (P1-4). Say so, unless the caller is already showing a more specific error.
  const undecryptableNotice = totp.secretUndecryptable
    ? 'Two-factor auth is enabled on this account but cannot be verified right now because of a server configuration problem. Contact an administrator — do not keep retrying codes.'
    : null;
  res.status(opts.status ?? 200).render('security', {
    userEmail: session.email,
    mfaEnabled: totp.enabled,
    // How many single-use recovery codes are still unspent, and (only in the response that just created them) the codes themselves.
    recoveryCodesRemaining: totp.enabled ? codesLeft : 0,
    newRecoveryCodes: opts.newCodes ?? null,
    pending: opts.pending ?? null,
    canChangePassword,
    recentLogins,
    mySessions,
    error: opts.error ?? undecryptableNotice,
    passwordError: opts.passwordError ?? null,
    csrf: issueSecurityCsrf(res),
  });
}

// The self-service "current password" check has no lockout bookkeeping (a
// wrong guess just rejects the form) because a live session already proved
// possession of *something* — but with zero throttling, anyone holding a
// stolen/replayed idp_portal cookie could unlimited-guess the real password.
// Scoped tightly to this one route, not a blanket portal-wide limiter.
const passwordChangeLimiter = createLimiter('password-change', { windowMs: 15 * 60_000, limit: 10 });

export function portalRouter(): Router {
  const router = Router();
  router.use((_req, res, next) => { res.set('cache-control', 'no-store'); next(); });

  // Home — requires an authenticated portal session.
  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = await sessionFromRequest(req);
      if (!session) return res.redirect('/portal/login');
      const isAdmin = session.groups.includes(IDP_CONFIG.adminGroup);
      const allow = await entitled(session.groups, session.email);
      const apps = catalog().filter((a) => allow.has(a.rp));
      // Admins get the console as a first-class tile, not just a corner link.
      if (isAdmin) apps.push(adminTile());
      res.render('portal', {
        apps,
        userName: session.name || session.email,
        userEmail: session.email,
        isAdmin,
        csrf: issueSecurityCsrf(res),
      });
    } catch (err) { next(err); }
  });

  // Begin SSO (auth-code + PKCE) against our own IdP — reuses the SSO session.
  router.get('/login', async (_req: Request, res: Response, next: NextFunction) => {
    try {
      const verifier = b64url(crypto.randomBytes(32));
      const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
      const state = b64url(crypto.randomBytes(16));
      const nonce = b64url(crypto.randomBytes(16));
      // Bind this flow to THIS browser. Without it, an attacker who completes an
      // authorization for their own account can hand the resulting code+state to
      // a victim, whose browser redeems it and is signed in as the attacker.
      const binding = createFlowBinding();
      await setWebSession('pending_portal', state, { verifier, nonce, bindingHash: binding.hash } satisfies Pending, PENDING_TTL_MS);
      res.cookie(PORTAL_BIND_COOKIE, binding.token, flowBindingCookieOptions(PORTAL_BIND_PATH, PENDING_TTL_MS, IDP_CONFIG.isProd));
      const params = new URLSearchParams({
        response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
        // ad_groups is its own scope now (P1-2); the portal's entitlement
        // filter and admin tile both read it, so it must be requested here or
        // every user lands on an empty launcher.
        scope: 'openid profile email ad_groups', state, nonce,
        code_challenge: challenge, code_challenge_method: 'S256',
      });
      res.redirect(`${ISS}/authorize?${params.toString()}`);
    } catch (err) { next(err); }
  });

  // Finish SSO: exchange code, verify id_token, store portal session.
  router.get('/callback', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const code = String(req.query.code ?? '');
      const state = String(req.query.state ?? '');
      const flow = await takeWebSession<Pending>('pending_portal', state);
      // Path must match the res.cookie() call in /login exactly or the browser
      // keeps it (same footgun already noted on the bridge handoff cookie).
      res.clearCookie(PORTAL_BIND_COOKIE, { path: PORTAL_BIND_PATH });
      if (!code || !flow) return res.status(400).render('error', { message: 'Invalid or expired portal login.' });
      // Browser-binding check BEFORE the token exchange — a request that cannot
      // prove it is the browser that started this flow must not cause the code
      // to be redeemed at all.
      if (!flowBindingMatches(cookieValues(req, PORTAL_BIND_COOKIE)[0], flow.bindingHash)) {
        return res.status(400).render('error', {
          message: 'This sign-in was started in a different browser or has expired — go back and sign in again.',
        });
      }

      const tokenRes = await fetch(`${INTERNAL}/token`, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID, client_secret: clientSecret, code_verifier: flow.verifier,
        }).toString(),
      });
      if (!tokenRes.ok) return res.status(502).render('error', { message: 'Portal token exchange failed.' });
      const tokens = (await tokenRes.json()) as { id_token?: string };
      if (!tokens.id_token) return res.status(502).render('error', { message: 'No id_token from IdP.' });

      // algorithms pinned — see the matching note in bridge/router.ts.
      const { payload } = await jwtVerify(tokens.id_token, JWKS, { issuer: IDP_CONFIG.issuer, audience: CLIENT_ID, algorithms: ['RS256'] });
      if (payload.nonce !== flow.nonce) return res.status(400).render('error', { message: 'Nonce mismatch.' });

      const key = await putPortalSession({
        accountId: String(payload.sub),
        name: String(payload.name ?? ''),
        email: String(payload.email ?? ''),
        groups: (payload[AD_GROUPS_CLAIM] as string[] | undefined) ?? [],
        idToken: tokens.id_token,
      });
      // path:'/' (not '/portal') so /admin can read the same session cookie.
      // Also purge any legacy cookie still scoped to /portal — a stale one would
      // otherwise be sent alongside (and before) the new cookie forever.
      res.clearCookie('idp_portal', { path: '/portal' });
      res.cookie('idp_portal', key, { httpOnly: true, sameSite: 'lax', secure: IDP_CONFIG.isProd, path: '/' });
      res.redirect('/portal');
    } catch (err) { next(err); }
  });

  // ── Security (self-service MFA, password, sessions, sign-in history) ──────
  router.get('/security', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      await renderSecurity(res, found.session, found.key);
    } catch (err) { next(err); }
  });

  // Start enrollment: generate a secret, show it (+ otpauth URI) with a confirm form.
  router.post('/security/totp/start', express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      if (!validateSecurityCsrf(req)) return res.redirect('/portal/security');
      const secret = generateTotpSecret();
      await setWebSession('totp_enroll', found.session.accountId, { secret }, 10 * 60_000);
      await renderSecurity(res, found.session, found.key, { pending: { secret, uri: otpauthUri(found.session.email, secret) } });
    } catch (err) { next(err); }
  });

  // Confirm enrollment with a live code from the app.
  router.post('/security/totp/confirm', express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      const { session, key } = found;
      if (!validateSecurityCsrf(req)) return res.redirect('/portal/security');
      const pending = await getWebSession<{ secret: string }>('totp_enroll', session.accountId);
      const code = String(req.body?.code ?? '');
      if (!pending) return res.redirect('/portal/security');

      const lockout = await checkMfaLockout(session.accountId);
      if (lockout.locked) {
        await renderSecurity(res, session, key, {
          pending: { secret: pending.secret, uri: otpauthUri(session.email, pending.secret) },
          error: 'Too many incorrect codes — try again in a few minutes.',
          status: 429,
        });
        return;
      }

      const matchedCounter = verifyTotp(pending.secret, code);
      if (matchedCounter === null) {
        await recordMfaAttempt(session.accountId, false);
        await renderSecurity(res, session, key, {
          pending: { secret: pending.secret, uri: otpauthUri(session.email, pending.secret) },
          error: 'That code is not valid — try the current code from your app.',
          status: 400,
        });
        return;
      }
      await recordMfaAttempt(session.accountId, true);
      // The confirmation code's counter becomes the initial replay high-water
      // mark, so the code just used to enroll cannot be immediately replayed at
      // the login MFA prompt — the two are seconds apart and share the ±1 window.
      await enableTotp(session.accountId, pending.secret, matchedCounter);
      await dropWebSession('totp_enroll', session.accountId);
      // The recovery codes are shown exactly once, in this response, so it renders the page itself instead of redirecting to a GET.
      const newCodes = await replaceRecoveryCodes(session.accountId);
      await writeAudit(req, session.email, 'user.mfa_enroll', session.email, { self: true, recoveryCodes: newCodes.length });
      await renderSecurity(res, session, key, { newCodes });
    } catch (err) { next(err); }
  });

  // Disable MFA (requires a current code — losing the device means asking an admin).
  router.post('/security/totp/disable', express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      const { session, key } = found;
      if (!validateSecurityCsrf(req)) return res.redirect('/portal/security');
      const totp = await getTotpState(session.accountId);
      const code = String(req.body?.code ?? '');

      const lockout = await checkMfaLockout(session.accountId);
      if (lockout.locked) {
        await renderSecurity(res, session, key, { error: 'Too many incorrect codes — try again in a few minutes.', status: 429 });
        return;
      }

      // Undecryptable secret: the user cannot produce a valid code for it and
      // never will. Offer the honest error rather than burning an attempt (and
      // eventually locking them out) against a secret the server cannot read.
      // Note they are NOT stuck: an admin can clear MFA for them.
      if (totp.secretUndecryptable) {
        await renderSecurity(res, session, key, {
          error: 'Two-factor auth cannot be verified right now because of a server configuration problem — contact an administrator.',
          status: 503,
        });
        return;
      }

      const matchedCounter = totp.enabled && totp.secret ? verifyTotp(totp.secret, code) : null;
      const replayed = matchedCounter !== null && totp.lastCounter !== null && matchedCounter <= totp.lastCounter;
      if (matchedCounter === null || replayed) {
        await recordMfaAttempt(session.accountId, false);
        await renderSecurity(res, session, key, {
          error: replayed
            ? 'That code has already been used — wait for your app to show the next one.'
            : 'Enter a valid current code to disable two-factor auth.',
          status: 400,
        });
        return;
      }
      const attemptResult = await recordMfaAttempt(session.accountId, true, matchedCounter);
      if (attemptResult.replay) {
        await renderSecurity(res, session, key, {
          error: 'That code has already been used — wait for your app to show the next one.',
          status: 400,
        });
        return;
      }
      await disableTotp(session.accountId);
      await writeAudit(req, session.email, 'user.mfa_disable', session.email, { self: true });
      res.redirect('/portal/security');
    } catch (err) { next(err); }
  });

  // A new set of recovery codes (the old set stops working at once). Needs a current authenticator code, the same proof turning
  // two-factor off needs, so a stolen portal cookie alone cannot mint codes that bypass the authenticator.
  router.post('/security/recovery-codes/regenerate', express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      const { session, key } = found;
      if (!validateSecurityCsrf(req)) return res.redirect('/portal/security');
      const totp = await getTotpState(session.accountId);
      const code = String(req.body?.code ?? '');

      if ((await checkMfaLockout(session.accountId)).locked) {
        await renderSecurity(res, session, key, { error: 'Too many incorrect codes — try again in a few minutes.', status: 429 });
        return;
      }
      if (!totp.enabled || totp.secretUndecryptable) {
        await renderSecurity(res, session, key, { error: 'Turn on two-factor auth first; recovery codes belong to your authenticator.', status: 400 });
        return;
      }
      const matchedCounter = totp.secret ? verifyTotp(totp.secret, code) : null;
      const replayed = matchedCounter !== null && totp.lastCounter !== null && matchedCounter <= totp.lastCounter;
      if (matchedCounter === null || replayed) {
        await recordMfaAttempt(session.accountId, false);
        await renderSecurity(res, session, key, {
          error: replayed ? 'That code has already been used — wait for your app to show the next one.' : 'Enter a valid current code to create new recovery codes.',
          status: 400,
        });
        return;
      }
      const attempt = await recordMfaAttempt(session.accountId, true, matchedCounter);
      if (attempt.replay) {
        await renderSecurity(res, session, key, { error: 'That code has already been used — wait for your app to show the next one.', status: 400 });
        return;
      }
      const newCodes = await replaceRecoveryCodes(session.accountId);
      await writeAudit(req, session.email, 'user.recovery_codes_regenerate', session.email, { self: true, recoveryCodes: newCodes.length });
      await renderSecurity(res, session, key, { newCodes });
    } catch (err) { next(err); }
  });

  // Self-service password change — local-source accounts only (see
  // canSelfChangePassword: AD accounts manage their password in AD). Since 2026-10-10 it ends ALL sessions, the current
  // one included, exactly like an admin reset: the person signs in again with the new password.
  router.post('/security/password/change', passwordChangeLimiter, express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      const { session, key } = found;
      if (!validateSecurityCsrf(req)) return res.redirect('/portal/security');

      if (!(await canSelfChangePassword(session.accountId))) {
        res.status(403).render('error', { message: 'Your password is managed outside the IdP and cannot be changed here.' });
        return;
      }

      const current = String(req.body?.current_password ?? '');
      const next = String(req.body?.new_password ?? '');
      const confirm = String(req.body?.confirm_password ?? '');

      if (!(await verifyCurrentPassword(session.accountId, current))) {
        await renderSecurity(res, session, key, { passwordError: 'Current password is incorrect.', status: 400 });
        return;
      }
      const policy = newPasswordProblem(next, session.email);
      if (policy) {
        await renderSecurity(res, session, key, { passwordError: policy, status: 400 });
        return;
      }
      if (next !== confirm) {
        await renderSecurity(res, session, key, { passwordError: 'New passwords do not match.', status: 400 });
        return;
      }
      if (next === current) {
        await renderSecurity(res, session, key, { passwordError: 'New password must be different from your current password.', status: 400 });
        return;
      }

      await completePasswordChange(session.accountId, await hashPassword(next));
      await writeAudit(req, session.email, 'user.password_change', session.email, { self: true });
      // A changed password must end every session minted under the old one, this one included: a stolen portal session
      // otherwise outlives the victim's password change (and could enrol its own TOTP). Sign in again with the new password.
      await revokeAllSessions(session.accountId, session.email).catch(() => { /* the password is already changed */ });
      res.clearCookie('idp_portal', { path: '/portal' });
      res.clearCookie('idp_portal', { path: '/' });
      res.redirect('/portal/login');
    } catch (err) { next(err); }
  });

  // Sign out a single one of the caller's OWN sessions (lost/stolen device,
  // or just tidying up) — the self-service counterpart of the admin console's
  // /admin/sessions/kill, but every delete below is scoped to this account/
  // email so it can never touch another user's session even given a guessed key.
  router.post('/security/sessions/kill', express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      const found = await sessionWithKeyFromRequest(req);
      if (!found) return res.redirect('/portal/login');
      const { session } = found;
      if (!validateSecurityCsrf(req)) return res.redirect('/portal/security');

      const kind = String(req.body?.kind ?? '');
      const key = String(req.body?.key ?? '');
      if (kind === 'portal') {
        await pool.query(
          `DELETE FROM idp_web_sessions WHERE kind = 'portal' AND encode(sha256(convert_to(key, 'UTF8')), 'hex') = $1 AND payload->>'accountId' = $2`,
          [key, session.accountId],
        );
      } else if (kind === 'gateway') {
        await pool.query(
          `DELETE FROM idp_web_sessions WHERE kind = 'gateway' AND encode(sha256(convert_to(key, 'UTF8')), 'hex') = $1 AND payload->>'email' = $2`,
          [key, session.email.toLowerCase()],
        );
      } else if (kind === 'sso') {
        await pool.query(
          `DELETE FROM oidc_artifacts WHERE kind = 'Session' AND id = $1 AND payload->>'accountId' = $2`,
          [key, session.accountId],
        );
      } else {
        res.redirect('/portal/security');
        return;
      }
      await writeAudit(req, session.email, 'user.session_kill', session.email, { self: true, kind, keyPrefix: key.slice(0, 12) });
      res.redirect('/portal/security');
    } catch (err) { next(err); }
  });

  // Full sign-out: drop the portal session AND end the IdP SSO session via
  // RP-initiated logout (/session/end). Without the second step the shared SSO
  // cookie silently re-authenticates the same user on the next click, which
  // makes sign-out appear broken and account switching impossible.
  //
  // POST + CSRF (was a bare GET) — an <img src="/portal/logout"> on any page a
  // signed-in user visits could otherwise silently sign them out and propagate
  // that to GMS/DMS with no user action.
  router.post('/logout', express.urlencoded({ extended: false }), async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateSecurityCsrf(req)) return res.redirect('/portal');
      let idToken: string | undefined;
      let email: string | undefined;
      let accountId: string | undefined;
      for (const v of cookieValues(req, 'idp_portal')) {
        const s = await getPortalSession(v);
        if (s?.idToken) idToken = s.idToken;
        if (s?.email) email = s.email;
        if (s?.accountId) accountId = s.accountId;
        await dropPortalSession(v);
      }
      res.clearCookie('idp_portal', { path: '/portal' });
      res.clearCookie('idp_portal', { path: '/' });

      // Full sweep — the same "sign out everywhere" the admin console's
      // revokeAllSessions does (SSO session/grants/tokens, gateway session, GMS,
      // DMS notify) — was previously only a best-effort GMS/DMS notify that left
      // the SSO session/grant alive, so a self-service sign-out didn't actually
      // end everything the way it silently promised to.
      if (accountId && email) {
        await revokeAllSessions(accountId, email).catch(() => { /* logged out regardless */ });
      } else {
        if (email) revokeGmsSessionsByEmail(email).catch(() => { /* logged out regardless */ });
        if (accountId) {
          notifyDmsLogout(accountId).catch(() => { /* logged out regardless */ });
          notifyAppLogouts(accountId).catch(() => { /* logged out regardless */ });
        }
      }

      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        post_logout_redirect_uri: `${ISS}/portal`,
      });
      if (idToken) params.set('id_token_hint', idToken);
      // P1-5: mark this as OUR sign-out so oidc-provider's end-session page may
      // auto-submit. Without the cookie it renders the real confirmation form,
      // which is what stops any third-party page from ending someone's entire
      // SSO session with a hidden <iframe src=".../session/end?client_id=...">.
      setLogoutIntent(res);
      res.redirect(`${ISS}/session/end?${params.toString()}`);
    } catch (err) { next(err); }
  });

  return router;
}
