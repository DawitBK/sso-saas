/**
 * What the sign-in log's `reason` column means, in words a person (or an administrator reading the log) can act on.
 * The reasons are written by the backend (auth/account.ts, interactions/router.ts); an unknown one is shown as-is rather than hidden.
 */
const REASONS: Record<string, string> = {
  invalid_credentials: 'Wrong email or password',
  inactive: 'Account is disabled',
  locked: 'Locked after too many wrong passwords',
  locked_ip: 'Blocked: too many failures from this address',
  account_conflict: 'Active Directory account clashes with a local one',
  mfa_failed: 'Wrong two-factor code',
  mfa_replay: 'Two-factor code already used',
  mfa_locked: 'Locked after too many wrong two-factor codes',
  mfa_unavailable: 'Two-factor unavailable (server problem)',
  mfa_recovery_used: 'Signed in with a recovery code',
};

export function loginReasonLabel(success: boolean, reason: string | null | undefined): string {
  if (reason && REASONS[reason]) return REASONS[reason];
  if (success) return 'Signed in';
  return reason ? reason.replace(/_/g, ' ') : 'Failed';
}

/** A successful sign-in that deserves a second look: the person used a recovery code, so the phone may be lost. */
export function isNotableSuccess(success: boolean, reason: string | null | undefined): boolean {
  return success && reason === 'mfa_recovery_used';
}
