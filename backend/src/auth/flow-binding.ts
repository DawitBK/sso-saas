/**
 * Browser-binding for in-flight authorization-code flows.
 *
 * The problem this solves (P1-1): a `state` value is unguessable, but it is not
 * *bound to anything*. Every relying-party leg in this platform stored the
 * pending flow (`verifier` + `nonce`) keyed only by `state`, then accepted
 * whatever browser later arrived at the callback carrying that `state`. So an
 * attacker who completed an authorization themselves — and therefore legitimately
 * holds a valid `code` + `state` pair for their OWN account — could feed that
 * pair to a victim's browser (a crafted link, an img/iframe to the callback, a
 * planted redirect) and the victim's browser would redeem it and be silently
 * signed in as the attacker. That is login CSRF / session fixation: the victim
 * then works inside the attacker's session, and anything they upload, approve,
 * or type lands in the attacker's account.
 *
 * The fix is the standard one: at flow start, mint a high-entropy token, keep
 * only its SHA-256 in the server-side pending record, and hand the raw token to
 * the browser as an httpOnly cookie scoped to the callback path. At the callback,
 * the cookie must be present and must hash to the stored value. The attacker can
 * copy the `code` and `state` out of their own URL bar, but they cannot write an
 * httpOnly cookie into the victim's browser for this origin — so the victim's
 * request fails closed before the token exchange happens.
 *
 * Hashing before comparing serves two purposes: the stored side is useless if
 * the pending row leaks, and both operands are always 32 bytes, which sidesteps
 * `timingSafeEqual`'s throw-on-length-mismatch and stops the token's length from
 * leaking through it.
 *
 * The GMS bridge's *handoff* hop (bridge/router.ts) already used exactly this
 * pattern one step later in the same flow; this module generalises it so the
 * authorize→callback hop — the one that actually establishes identity — gets the
 * same treatment, and so all three legs share one implementation instead of
 * three hand-rolled copies.
 */

import crypto from 'node:crypto';

export interface FlowBinding {
  /** Raw token — goes to the browser in an httpOnly cookie. Never stored. */
  token: string;
  /** SHA-256 of the token, hex — this is what goes in the pending record. */
  hash: string;
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/** Mint a fresh binding at flow start. */
export function createFlowBinding(): FlowBinding {
  const token = crypto.randomBytes(32).toString('hex');
  return { token, hash: sha256Hex(token) };
}

/**
 * Constant-time check of a presented cookie against a stored hash.
 *
 * Fails closed on every degenerate input: no cookie, no stored hash, or a
 * stored hash that isn't parseable hex of the right length. That last case is
 * what a pending record written by the *previous* build looks like (it has no
 * binding field at all), so any authorization that was already in flight across
 * a deploy is rejected rather than waved through — a ~10-minute window in which
 * an affected user simply starts the login again.
 */
export function flowBindingMatches(presentedToken: string | undefined, storedHash: unknown): boolean {
  if (!presentedToken || typeof storedHash !== 'string' || storedHash.length !== 64) return false;
  const expected = Buffer.from(storedHash, 'hex');
  if (expected.length !== 32) return false;
  const presented = Buffer.from(sha256Hex(presentedToken), 'hex');
  return crypto.timingSafeEqual(presented, expected);
}

/**
 * Cookie options for a binding token. `sameSite: 'lax'` is required, not merely
 * chosen: the callback is reached by a top-level cross-site redirect from the
 * IdP's authorize endpoint, and 'strict' would withhold the cookie on exactly
 * that navigation and break every login. 'lax' still withholds it from the
 * cross-site POST/subresource shapes an attacker would use.
 */
export function flowBindingCookieOptions(path: string, ttlMs: number, isProd: boolean) {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: isProd,
    path,
    maxAge: ttlMs,
  };
}
