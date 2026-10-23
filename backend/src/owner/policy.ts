/**
 * Owner verification: the numbers and switches in ONE dependency-free place (config.ts reads it before anything else is loaded).
 *
 * OWNER_VERIFICATION_REQUIRED: whether an owner-only operation needs a valid owner authorisation ticket. Default true in production, the mirror
 * and anything with a non-local issuer; false in development and tests (owner decision: development stays unrestricted). `explicit` says the
 * value came from the environment, so a production process that turned it off is reported at every start and refused by the release preflight.
 * When it is required and the owner has not enrolled, owner-only operations are REFUSED (OWNER_NOT_ENROLLED), never allowed.
 */
export function parseOwnerVerificationRequired(raw: string | undefined, nodeEnv: string, isProd: boolean): { required: boolean; explicit: boolean } {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'true') return { required: true, explicit: true };
  if (v === 'false') return { required: false, explicit: true };
  return { required: isProd || nodeEnv === 'production' || nodeEnv === 'mirror', explicit: false };
}

/**
 * OWNER_AUTHENTICATOR_REQUIRED: whether a NEW enrolment (owner:enroll, owner:recover) includes the phone authenticator. Default false (owner decision
 * 2026-10-21: the owner does not want the phone step); only the word `true` turns it on. It never changes how an EXISTING enrolment is verified:
 * the factors an enrolment was made with are sealed inside the store (store.ts `factors`) and verification always demands those.
 */
export function parseOwnerAuthenticatorRequired(raw: string | undefined): { required: boolean; explicit: boolean } {
  const v = (raw ?? '').trim().toLowerCase();
  if (v === 'true') return { required: true, explicit: true };
  return { required: false, explicit: v === 'false' };
}

/** A ticket is good for this long after the sequence finishes. */
export const TICKET_TTL_SECONDS = 300;
/** A run of the sequence must be completed within this long of starting it. */
export const CHALLENGE_TTL_SECONDS = 600;
/** The emailed code is good for this long. */
export const EMAIL_CODE_TTL_SECONDS = 600;
export const EMAIL_CODE_DIGITS = 8;
/** Wrong guesses allowed on one emailed code before it is void (the failure also counts toward the lockout). */
export const EMAIL_CODE_MAX_ATTEMPTS = 5;
/** Sends per run and the pause between two sends; and sends per hour across everything. */
export const EMAIL_MAX_SENDS_PER_CHALLENGE = 3;
export const EMAIL_RESEND_SECONDS = 60;
export const EMAIL_MAX_SENDS_PER_HOUR = 10;
/** Runs of the sequence started per hour. */
export const MAX_CHALLENGES_PER_HOUR = 20;
/** Consecutive failures that lock the sequence, and the escalating lock durations (seconds) by level. The last one repeats. */
export const LOCK_AFTER_FAILURES = 5;
export const LOCK_SECONDS_BY_LEVEL = [300, 900, 3600, 21_600, 86_400] as const;
/** Offline recovery codes made at enrolment. */
export const RECOVERY_CODE_COUNT = 10;
export const SECURITY_QUESTION_COUNT = 3;
export const MAX_ANSWER_LENGTH = 200;

/** Seconds a lock of the given level lasts (level 0 is the first lock). */
export function lockSeconds(level: number): number {
  const i = Math.max(0, Math.min(Math.floor(level), LOCK_SECONDS_BY_LEVEL.length - 1));
  return LOCK_SECONDS_BY_LEVEL[i] as number;
}
