/**
 * Interaction router — renders our own login + consent screens and completes
 * oidc-provider interactions. Wired via the provider's `interactions.url`.
 */

import { Router, type Request, type Response, type NextFunction } from 'express';
import type Provider from 'oidc-provider';
import { IDP_CONFIG } from '../config.js';
import { authenticateUser } from '../auth/account.js';
import { checkMfaLockout, completePasswordChange, getTotpState, recordMfaAttempt } from '../auth/local-users.js';
import { hashPassword } from '../auth/password.js';
import { verifyTotp } from '../auth/totp.js';
import { pool } from '../db/pool.js';
import { setWebSession, takeWebSession, getWebSession } from '../db/web-sessions.js';
import { issueCsrf, validateCsrf } from './csrf.js';
import { parseOrRenderView } from '../validation/parse.js';
import { formatZodIssues } from '../validation/format.js';
import { LoginBodySchema, PasswordChangeBodySchema, TotpBodySchema } from './schemas.js';

/** Verified-but-not-finished logins parked between steps (password change /
 *  MFA code), keyed by interaction uid. */
const PWCHANGE_TTL_MS = 10 * 60_000;
const MFA_TTL_MS = 10 * 60_000;

/** Record a sign-in attempt for the admin Sign-ins page + anomaly alerts. */
async function recordLoginEvent(req: Request, email: string, success: boolean, reason = ''): Promise<void> {
  try {
    await pool.query(
      'INSERT INTO idp_login_events (email, success, reason, ip, user_agent) VALUES ($1, $2, $3, $4, $5)',
      [email.toLowerCase(), success, reason, req.ip ?? '', String(req.headers['user-agent'] ?? '').slice(0, 300)],
    );
  } catch {
    // Telemetry must never block sign-in.
  }
}

/** Finish the parked login, honoring the password-change → MFA step order. */
async function proceedAfterPassword(
  provider: Provider,
  req: Request,
  res: Response,
  uid: string,
  clientName: string,
  accountId: string,
): Promise<void> {
  const totp = await getTotpState(accountId);
  if (totp.enabled && totp.secret) {
    await setWebSession('mfa', uid, { accountId }, MFA_TTL_MS);
    res.render('totp', { uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), error: null });
    return;
  }
  await provider.interactionFinished(
    req, res,
    { login: { accountId, remember: true } },
    { mergeWithLastSubmission: false },
  );
}

// One message for every failure reason (bad password, locked, inactive) — the
// distinct per-reason messages this used to show let an unauthenticated caller
// enumerate which accounts exist and their lockout/active state. The real
// reason is still recorded in idp_login_events for admins (recordLoginEvent).
const GENERIC_LOGIN_ERROR = 'Incorrect email or password, or this account is temporarily unavailable.';

/** Build (or extend) the Grant for the current consent interaction, then finish. */
async function finalizeConsent(
  provider: Provider,
  req: Request,
  res: Response,
  details: Awaited<ReturnType<Provider['interactionDetails']>>,
): Promise<void> {
  const { prompt, params, session } = details;
  const d = prompt.details as {
    missingOIDCScope?: string[];
    missingOIDCClaims?: string[];
    missingResourceScopes?: Record<string, string[]>;
  };
  const accountId = session!.accountId;
  let grant = details.grantId ? await provider.Grant.find(details.grantId) : undefined;
  if (!grant) grant = new provider.Grant({ accountId, clientId: String(params.client_id) });
  if (d.missingOIDCScope) grant.addOIDCScope(d.missingOIDCScope.join(' '));
  if (d.missingOIDCClaims) grant.addOIDCClaims(d.missingOIDCClaims);
  if (d.missingResourceScopes) {
    for (const [indicator, scopes] of Object.entries(d.missingResourceScopes)) {
      grant.addResourceScope(indicator, scopes.join(' '));
    }
  }
  const grantId = await grant.save();
  await provider.interactionFinished(
    req, res,
    { consent: details.grantId ? {} : { grantId } },
    { mergeWithLastSubmission: true },
  );
}

export function interactionRouter(provider: Provider): Router {
  const router = Router();

  // Prevent caching of interaction pages (they carry per-session state).
  router.use((_req, res, next) => {
    res.set('cache-control', 'no-store');
    next();
  });

  // Render the appropriate screen for the current prompt.
  router.get('/:uid', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      const { prompt, params, uid } = details;
      const client = await provider.Client.find(String(params.client_id));
      const clientName = client?.clientName ?? String(params.client_id);
      const csrf = issueCsrf(res, IDP_CONFIG.isProd);

      if (prompt.name === 'login') {
        return res.render('login', { uid, clientName, csrf, error: null, email: '' });
      }
      if (prompt.name === 'consent') {
        // All registered clients are first-party/trusted, so auto-grant consent
        // — this is what makes hopping between apps seamless (no consent click).
        // (Render the consent screen instead if you later add third-party clients.)
        return finalizeConsent(provider, req, res, details);
      }
      return res.status(400).render('error', { message: `Unsupported prompt: ${prompt.name}` });
    } catch (err) {
      next(err);
    }
  });

  // Handle credential submission.
  router.post('/:uid/login', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      const { params, uid } = details;
      const client = await provider.Client.find(String(params.client_id));
      const clientName = client?.clientName ?? String(params.client_id);
      const email = String(req.body?.email ?? '');

      if (!validateCsrf(req)) {
        return res.status(403).render('login', { uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), error: 'Session expired, please try again.', email });
      }

      const parsed = parseOrRenderView(LoginBodySchema, req.body, res, 'login', {
        uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), email,
      });
      if (!parsed) return;

      const result = await authenticateUser(parsed.data.email, parsed.data.password);
      if (!result.ok) {
        await recordLoginEvent(req, parsed.data.email, false, result.reason);
        return res.status(401).render('login', {
          uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd),
          error: GENERIC_LOGIN_ERROR, email: parsed.data.email,
        });
      }
      await recordLoginEvent(req, parsed.data.email, true);

      // Admin-reset password: credentials verified, but a new password must be
      // set before the SSO session is established. Park the verified login and
      // show the change screen.
      if (result.mustChangePassword) {
        await setWebSession('pwchange', uid, { accountId: result.accountId }, PWCHANGE_TTL_MS);
        return res.render('change-password', { uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), error: null });
      }

      // Next step: MFA code if enrolled, else establish the SSO session.
      await proceedAfterPassword(provider, req, res, uid, clientName, result.accountId);
    } catch (err) {
      next(err);
    }
  });

  // MFA step: verify the authenticator code, then complete the parked login.
  router.post('/:uid/totp', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      const { params, uid } = details;
      const client = await provider.Client.find(String(params.client_id));
      const clientName = client?.clientName ?? String(params.client_id);
      const rerender = (error: string, status = 400) =>
        res.status(status).render('totp', { uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), error });

      if (!validateCsrf(req)) return rerender('Session expired, please try again.', 403);

      const parked = await getWebSession<{ accountId: string }>('mfa', uid);
      if (!parked) return rerender('This sign-in expired — start again.');

      const { rows: acctRows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [parked.accountId]);
      const accountEmail = acctRows[0]?.email ?? parked.accountId;

      const lockout = await checkMfaLockout(parked.accountId);
      if (lockout.locked) {
        await recordLoginEvent(req, accountEmail, false, 'mfa_locked');
        return rerender('Too many incorrect codes — try again in a few minutes.', 429);
      }

      const totp = await getTotpState(parked.accountId);
      const codeParsed = TotpBodySchema.safeParse(req.body);
      if (!codeParsed.success) return rerender(formatZodIssues(codeParsed.error));
      const { code } = codeParsed.data;
      if (!totp.secret || !verifyTotp(totp.secret, code)) {
        await recordMfaAttempt(parked.accountId, false);
        await recordLoginEvent(req, accountEmail, false, 'mfa_failed');
        return rerender('That code is not valid — try the current code from your app.', 401);
      }
      await recordMfaAttempt(parked.accountId, true);

      await takeWebSession('mfa', uid);
      await provider.interactionFinished(
        req, res,
        { login: { accountId: parked.accountId, remember: true } },
        { mergeWithLastSubmission: false },
      );
    } catch (err) {
      next(err);
    }
  });

  // Forced password change (after an admin reset): set the new password, then
  // complete the parked login.
  router.post('/:uid/password', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      const { params, uid } = details;
      const client = await provider.Client.find(String(params.client_id));
      const clientName = client?.clientName ?? String(params.client_id);
      const rerender = (error: string, status = 400) =>
        res.status(status).render('change-password', { uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), error });

      if (!validateCsrf(req)) return rerender('Session expired, please try again.', 403);

      const parked = await getWebSession<{ accountId: string }>('pwchange', uid);
      if (!parked) return rerender('This password-change session expired — sign in again.', 400);

      const pwParsed = PasswordChangeBodySchema.safeParse(req.body);
      if (!pwParsed.success) return rerender(formatZodIssues(pwParsed.error));
      const { password, confirm } = pwParsed.data;
      if (password.length < 8) return rerender('Password must be at least 8 characters.');
      if (password !== confirm) return rerender('Passwords do not match.');

      await completePasswordChange(parked.accountId, await hashPassword(password));
      await takeWebSession('pwchange', uid); // consume only after success

      // Password set — continue to the MFA step if enrolled, else finish.
      await proceedAfterPassword(provider, req, res, uid, clientName, parked.accountId);
    } catch (err) {
      next(err);
    }
  });

  // Handle consent confirmation — build/extend the Grant, then finish.
  router.post('/:uid/confirm', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const details = await provider.interactionDetails(req, res);
      if (!validateCsrf(req)) return res.status(403).render('error', { message: 'Session expired, please try again.' });
      await finalizeConsent(provider, req, res, details);
    } catch (err) {
      next(err);
    }
  });

  // User declined consent.
  router.post('/:uid/abort', async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!validateCsrf(req)) return res.status(403).render('error', { message: 'Session expired, please try again.' });
      await provider.interactionFinished(
        req, res,
        { error: 'access_denied', error_description: 'End-user aborted interaction' },
        { mergeWithLastSubmission: false },
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}
