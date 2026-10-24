/**
 * Interaction router — renders our own login + consent screens and completes
 * oidc-provider interactions. Wired via the provider's `interactions.url`.
 */

import { newPasswordProblem } from '../auth/password-policy.js';
import { clientIpOf } from '../http/client-ip.js';
import { findPlatformAdminForLogin } from '../auth/platform-admin.js';
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
import { logger } from '../logging/logger.js';
import { GateBusyError } from '../infrastructure/workGate.js';
import { consumeRecoveryCode, looksLikeTotp, normalizeRecoveryCode, recoveryCodesRemaining } from '../auth/recovery-codes.js';
import { accountHasAppAccess } from '../auth/app-roles.js';

/** What a person is told when an application managed from the console has not been given to them. */
export const APP_ACCESS_DENIED_MESSAGE = 'You have not been given access to this application. Ask an administrator.';

/** Verified-but-not-finished logins parked between steps (password change /
 *  MFA code), keyed by interaction uid. */
const PWCHANGE_TTL_MS = 10 * 60_000;
const MFA_TTL_MS = 10 * 60_000;

/**
 * Record a sign-in attempt for the admin Sign-ins page + anomaly alerts.
 *
 * This is NOT just telemetry, which is what the previous bare `catch {}` here
 * assumed. `idp_login_events` is the ONLY brute-force gate that covers AD
 * accounts: auth/account.ts's recentFailureCount() counts failed rows in this
 * table over a 15-minute window, and the local user store's own column-based
 * lockout does not apply to AD binds. So if writes here start failing — a
 * constraint, a full disk, a revoked grant — the AD lockout silently stops
 * working, and with a silent catch there was no signal anywhere that it had.
 *
 * Still never throws (a telemetry failure must not deny a legitimate sign-in),
 * but now says so loudly.
 */
async function recordLoginEvent(req: Request, email: string, success: boolean, reason = ''): Promise<void> {
  try {
    // Backstop for every caller (password step, every MFA step): the platform
    // administrator's attempts are never recorded, whichever form of its address
    // the caller holds (the real one typed at the form, or the stored pseudonym).
    if (await findPlatformAdminForLogin(email)) return;
    await pool.query(
      'INSERT INTO idp_login_events (email, success, reason, ip, user_agent) VALUES ($1, $2, $3, $4, $5)',
      [email.toLowerCase(), success, reason, clientIpOf(req), String(req.headers['user-agent'] ?? '').slice(0, 300)],
    );
  } catch (err) {
    logger.error(
      { err, success, reason },
      '[idp:auth:ALERT] login-event write failed — the AD brute-force gate (recentFailureCount) reads this table and is now degraded',
    );
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
  if (totp.enabled && !totp.secret) {
    // MFA is switched on for this account but its secret cannot be read (key rotated, restore without the matching
    // env file, a damaged row). Letting the sign-in through on the password alone would turn every enrolled account,
    // administrators included, into a password-only account without anyone noticing. Fail closed and say so.
    const { rows } = await pool.query<{ email: string }>('SELECT email FROM idp_users WHERE id = $1', [accountId]);
    await recordLoginEvent(req, rows[0]?.email ?? accountId, false, 'mfa_unavailable');
    logger.error({ accountId }, '[idp:auth:ALERT] MFA is enabled but its secret is unreadable — sign-in refused (fail closed)');
    res.status(503).render('login', {
      uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd), email: rows[0]?.email ?? '',
      error: 'Two-factor sign-in is temporarily unavailable — this is a server problem, not your password. Contact an administrator.',
    });
    return;
  }
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
  // An application managed from the console (auth/app-roles.ts) is only for people who hold a role in it. Every authorization of
  // such an application reaches this step (oidc/provider.ts loadExistingGrant), so a removed role stops the next sign-in.
  if (!(await accountHasAppAccess(accountId, String(params.client_id)))) {
    logger.info({ accountId, clientId: String(params.client_id) }, '[idp:access] sign-in refused: the person holds no role in this application');
    await provider.interactionFinished(
      req, res,
      { error: 'access_denied', error_description: APP_ACCESS_DENIED_MESSAGE },
      { mergeWithLastSubmission: false },
    );
    return;
  }
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

      // req.ip is the lockout gate's second dimension (P1-17) — without it the
      // gate degrades to the old email-only behaviour, which is DoS-able. Needs
      // `trust proxy` set (main.ts) for this to be the real client address
      // behind Apache rather than the proxy's own.
      let result: Awaited<ReturnType<typeof authenticateUser>>;
      try {
        result = await authenticateUser(parsed.data.email, parsed.data.password, clientIpOf(req));
      } catch (err) {
        // Too many password checks are already running or waiting (infrastructure/workGate.ts). This is the server being busy, not a
        // wrong password: say so, do not record a failed sign-in, and ask the browser to retry shortly.
        if (err instanceof GateBusyError) {
          logger.warn({ reason: err.reason }, '[idp:auth] sign-in turned away: password checks are saturated');
          res.set('retry-after', '5');
          return res.status(503).render('login', {
            uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd),
            error: 'Sign-in is very busy right now. Please try again in a few seconds.', email: parsed.data.email,
          });
        }
        throw err;
      }
      // The platform administrator's sign-ins (and failed attempts at its address)
      // are not recorded anywhere: nothing to list, and nothing to lock it out with.
      if (!result.ok) {
        if (!result.platformAdmin) await recordLoginEvent(req, parsed.data.email, false, result.reason);
        return res.status(401).render('login', {
          uid, clientName, csrf: issueCsrf(res, IDP_CONFIG.isProd),
          error: GENERIC_LOGIN_ERROR, email: parsed.data.email,
        });
      }
      if (!result.platformAdmin) await recordLoginEvent(req, parsed.data.email, true);

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

      // A recovery code instead of an authenticator code (lost phone). Handled BEFORE the undecryptable-secret refusal below on
      // purpose: someone whose authenticator secret can no longer be read is exactly who needs a recovery code. A wrong code counts
      // toward the same five-attempt lockout as a wrong authenticator code.
      if (!looksLikeTotp(code) && normalizeRecoveryCode(code)) {
        if (!(await consumeRecoveryCode(parked.accountId, code))) {
          await recordMfaAttempt(parked.accountId, false);
          await recordLoginEvent(req, accountEmail, false, 'mfa_failed');
          return rerender('That recovery code is not valid, or it has already been used.', 401);
        }
        await recordMfaAttempt(parked.accountId, true);
        const left = await recoveryCodesRemaining(parked.accountId);
        await recordLoginEvent(req, accountEmail, true, 'mfa_recovery_used');
        logger.info({ accountId: parked.accountId, left }, '[idp:auth] signed in with a two-factor recovery code');
        await takeWebSession('mfa', uid);
        await provider.interactionFinished(
          req, res,
          { login: { accountId: parked.accountId, remember: true } },
          { mergeWithLastSubmission: false },
        );
        return;
      }

      // The stored secret exists but cannot be decrypted with the configured
      // TOTP_ENCRYPTION_KEY (P1-4). Crucially, do NOT call recordMfaAttempt here:
      // this is a server misconfiguration, not a wrong code, and counting it was
      // exactly the mechanism that silently locked out every enrolled user five
      // attempts after a key change. Fail loudly, burn nothing.
      if (totp.secretUndecryptable) {
        await recordLoginEvent(req, accountEmail, false, 'mfa_unavailable');
        return rerender(
          'Two-factor sign-in is temporarily unavailable — this is a server problem, not your code. Contact an administrator.',
          503,
        );
      }

      const matchedCounter = totp.secret ? verifyTotp(totp.secret, code) : null;
      if (matchedCounter === null) {
        await recordMfaAttempt(parked.accountId, false);
        await recordLoginEvent(req, accountEmail, false, 'mfa_failed');
        return rerender('That code is not valid — try the current code from your app.', 401);
      }

      // Replay guard (P1-4). verifyTotp accepts a ±1 step window, so a single
      // observed code stays cryptographically valid for up to 90 seconds; without
      // this check it could be submitted more than once inside that window.
      // Counted as a failed attempt on purpose: a resubmitted code is either a
      // replay attempt or a double-submit, and neither should get free retries.
      if (totp.lastCounter !== null && matchedCounter <= totp.lastCounter) {
        await recordMfaAttempt(parked.accountId, false);
        await recordLoginEvent(req, accountEmail, false, 'mfa_replay');
        return rerender('That code has already been used — wait for your app to show the next one.', 401);
      }

      const attemptResult = await recordMfaAttempt(parked.accountId, true, matchedCounter);
      if (attemptResult.replay) {
        // Lost the race: another request claimed this counter between our
        // read of totp.lastCounter above and this UPDATE committing. Same
        // response as the in-app check above — from the client's point of
        // view this is indistinguishable from a plain replay.
        await recordLoginEvent(req, accountEmail, false, 'mfa_replay');
        return rerender('That code has already been used — wait for your app to show the next one.', 401);
      }

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
      { const policy = newPasswordProblem(password); if (policy) return rerender(policy); }
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
