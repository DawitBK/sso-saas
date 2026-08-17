/**
 * SSO app-launcher portal — Model A: the authenticated home page staff land on.
 *
 * The portal is itself an OIDC relying party of this IdP, so it reuses the shared
 * SSO session to learn who is signed in (no extra prompt if already logged in
 * elsewhere), greets them, and shows only the apps they're entitled to
 * (`idp_app_entitlements`). Each tile launches that app's SSO flow.
 */

import express, { Router, type Request, type Response, type NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import crypto from 'node:crypto';
import { AD_GROUPS_CLAIM, IDP_CONFIG } from '../config.js';
import { pool } from '../db/pool.js';
import { getPortalSession, putPortalSession, dropPortalSession, type PortalSession } from './session.js';
import { catalog, adminTile, entitled } from './catalog.js';
import { setWebSession, takeWebSession, getWebSession, dropWebSession } from '../db/web-sessions.js';
import { revokeGmsSessionsByEmail } from '../bridge/gms.js';
import { notifyDmsLogout } from '../auth/logout-notify.js';
import { revokeAllSessions } from '../auth/revoke.js';
import {
  checkMfaLockout, getTotpState, enableTotp, disableTotp, recordMfaAttempt,
  canSelfChangePassword, verifyCurrentPassword, completePasswordChange,
} from '../auth/local-users.js';
import { generateTotpSecret, verifyTotp, otpauthUri } from '../auth/totp.js';
import { hashPassword } from '../auth/password.js';
import { writeAudit } from '../admin/audit.js';

const CLIENT_ID = 'portal';
const ISS = IDP_CONFIG.issuer.replace(/\/$/, '');
const INTERNAL = IDP_CONFIG.internalUrl.replace(/\/$/, '');
const REDIRECT_URI = `${ISS}/portal/callback`;
const JWKS = createRemoteJWKSet(new URL(`${INTERNAL}/jwks`));
const clientSecret = IDP_CONFIG.clientSeed.find((c) => c.client_id === CLIENT_ID)?.client_secret ?? '';

interface Pending { verifier: string; nonce: string }
const PENDING_TTL_MS = 10 * 60_000;
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
  const token = crypto.randomBytes(24).toString('hex');
  // Prefixed with publicBasePath — see the matching note in admin/csrf.ts.
  res.cookie('idp_portal_csrf', token, { httpOnly: true, sameSite: 'lax', secure: IDP_CONFIG.isProd, path: `${IDP_CONFIG.publicBasePath}/portal` });
  return token;
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
    ...webRows.map((r) => ({
      kind: r.kind, key: r.key, createdAt: r.created_at, expiresAt: r.expires_at,
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
  opts: { pending?: { secret: string; uri: string } | null; error?: string | null; passwordError?: string | null; status?: number } = {},
): Promise<void> {
  const [totp, canChangePassword, recentLogins, mySessions] = await Promise.all([
    getTotpState(session.accountId),
    canSelfChangePassword(session.accountId),
    recentLoginEventsFor(session.email),
    myOwnedSessions(session, currentPortalKey),
  ]);
  res.status(opts.status ?? 200).render('security', {
    userEmail: session.email,
    mfaEnabled: totp.enabled,
    pending: opts.pending ?? null,
    canChangePassword,
    recentLogins,
    mySessions,
    error: opts.error ?? null,
    passwordError: opts.passwordError ?? null,
    csrf: issueSecurityCsrf(res),
  });
}

// The self-service "current password" check has no lockout bookkeeping (a
// wrong guess just rejects the form) because a live session already proved
// possession of *something* — but with zero throttling, anyone holding a
// stolen/replayed idp_portal cookie could unlimited-guess the real password.
// Scoped tightly to this one route, not a blanket portal-wide limiter.
const passwordChangeLimiter = rateLimit({ windowMs: 15 * 60_000, limit: 10, standardHeaders: true, legacyHeaders: false });

export function portalRouter(): Router {
  const router = Router();
  router.use((_req, res, next) => { res.set('cache-control', 'no-store'); next(); });

  // Home — requires an authenticated portal session.
  router.get('/', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const session = await sessionFromRequest(req);
      if (!session) return res.redirect('/portal/login');
      const isAdmin = session.groups.includes(IDP_CONFIG.adminGroup);
      const allow = await entitled(session.groups);
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
      await setWebSession('pending_portal', state, { verifier, nonce } satisfies Pending, PENDING_TTL_MS);
      const params = new URLSearchParams({
        response_type: 'code', client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
        scope: 'openid profile email', state, nonce,
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
      if (!code || !flow) return res.status(400).render('error', { message: 'Invalid or expired portal login.' });

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

      const { payload } = await jwtVerify(tokens.id_token, JWKS, { issuer: IDP_CONFIG.issuer, audience: CLIENT_ID });
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

      if (!verifyTotp(pending.secret, code)) {
        await recordMfaAttempt(session.accountId, false);
        await renderSecurity(res, session, key, {
          pending: { secret: pending.secret, uri: otpauthUri(session.email, pending.secret) },
          error: 'That code is not valid — try the current code from your app.',
          status: 400,
        });
        return;
      }
      await recordMfaAttempt(session.accountId, true);
      await enableTotp(session.accountId, pending.secret);
      await dropWebSession('totp_enroll', session.accountId);
      await writeAudit(req, session.email, 'user.mfa_enroll', session.email, { self: true });
      res.redirect('/portal/security');
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

      if (!totp.enabled || !totp.secret || !verifyTotp(totp.secret, code)) {
        await recordMfaAttempt(session.accountId, false);
        await renderSecurity(res, session, key, { error: 'Enter a valid current code to disable two-factor auth.', status: 400 });
        return;
      }
      await recordMfaAttempt(session.accountId, true);
      await disableTotp(session.accountId);
      await writeAudit(req, session.email, 'user.mfa_disable', session.email, { self: true });
      res.redirect('/portal/security');
    } catch (err) { next(err); }
  });

  // Self-service password change — local-source accounts only (see
  // canSelfChangePassword: AD accounts manage their password in AD). Does not
  // force sign-out of other sessions the way an admin reset does — the caller
  // already proved possession of the current password from an already-live
  // session, so (consistent with TOTP enable/disable just above, which also
  // don't revoke anything) only future logins are affected.
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
      if (next.length < 8) {
        await renderSecurity(res, session, key, { passwordError: 'New password must be at least 8 characters.', status: 400 });
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
      res.redirect('/portal/security');
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
          `DELETE FROM idp_web_sessions WHERE kind = 'portal' AND key = $1 AND payload->>'accountId' = $2`,
          [key, session.accountId],
        );
      } else if (kind === 'gateway') {
        await pool.query(
          `DELETE FROM idp_web_sessions WHERE kind = 'gateway' AND key = $1 AND payload->>'email' = $2`,
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
        if (accountId) notifyDmsLogout(accountId).catch(() => { /* logged out regardless */ });
      }

      const params = new URLSearchParams({
        client_id: CLIENT_ID,
        post_logout_redirect_uri: `${ISS}/portal`,
      });
      if (idToken) params.set('id_token_hint', idToken);
      res.redirect(`${ISS}/session/end?${params.toString()}`);
    } catch (err) { next(err); }
  });

  return router;
}
