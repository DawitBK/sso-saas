/**
 * Refusals for console actions on a user account, shared by the Next console's
 * /api/v1/admin handlers and the legacy console (admin/access.ts) so the two cannot
 * disagree. Each returns the message to show, or null when the action is allowed.
 */

export const SELF_DISABLE_MESSAGE =
  'You cannot disable your own account — ask another administrator.';

/** An administrator may not disable (or toggle) their own account: it would sign them out of
 *  the console they are working in and, if they are the last administrator, lock everyone out. */
export function selfDisableRefusal(actorAccountId: string | undefined, targetUserId: string): string | null {
  return actorAccountId && actorAccountId === targetUserId ? SELF_DISABLE_MESSAGE : null;
}

export const AD_PASSWORD_RESET_MESSAGE =
  "This account signs in with Active Directory, so its password is managed in AD. Reset it there; setting a password in SSO would create a second, SSO-only credential that outlives the AD password.";

/** The console's Reset password sets a local, SSO-only password. That is only right for a
 *  local account. */
export function passwordResetRefusal(source: string | null | undefined): string | null {
  return source === 'local' ? null : AD_PASSWORD_RESET_MESSAGE;
}
