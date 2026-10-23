/**
 * The owner's security questions: a SUPPLEMENTARY factor (never the only one). The answers are typed once at a terminal (`npm run owner:enroll`),
 * normalised, mixed with a secret key from the key file, and stretched with scrypt and a random salt per answer. Only the result is stored (inside
 * the sealed store). They are compared in constant time and never shown again, logged or sent anywhere.
 *
 * scrypt rather than argon2id: argon2 is not a dependency of SSO and node:crypto has scrypt built in (the password gate already uses it). The
 * parameters below (N=2^17, r=8, p=1: about 128 MB and a few tenths of a second) are the OWASP minimum-class settings for scrypt and are stored with
 * each hash, so they can be raised later without invalidating old hashes. Answers like a favourite film have little entropy, which is why the keyed
 * pre-hash matters: without the key file, a copy of the hashes cannot even be guessed at.
 */
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { MAX_ANSWER_LENGTH } from './policy.js';
import { keyedHash, safeEqual, type StoreKeys } from './seal.js';

export interface KdfParams {
  logN: number;
  r: number;
  p: number;
}

export const DEFAULT_KDF: KdfParams = { logN: 17, r: 8, p: 1 };
let kdf: KdfParams = DEFAULT_KDF;

/** Test-only: weaker parameters so a unit test is not slow. Refuses to run outside NODE_ENV=test, so production can never be weakened by it. */
export function __setKdfParamsForTests(params: KdfParams): void {
  if (process.env.NODE_ENV !== 'test') throw new Error('__setKdfParamsForTests is for tests only');
  kdf = params;
}

/** trim, Unicode-normalise and strip accents, lower-case, collapse runs of whitespace. Two spellings a person would call "the same" give the same string. */
export function normaliseAnswer(raw: string): string {
  return String(raw)
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/** Why an answer cannot be used (at enrolment), or null. A blank or one-character answer is refused: it would be guessed at once. */
export function answerProblem(raw: string): string | null {
  const n = normaliseAnswer(raw);
  if (n.length < 2) return 'The answer is too short.';
  if (n.length > MAX_ANSWER_LENGTH) return `The answer is longer than ${MAX_ANSWER_LENGTH} characters.`;
  return null;
}

const scryptAsync = promisify(crypto.scrypt) as (pw: string, salt: Buffer, len: number, opts: crypto.ScryptOptions) => Promise<Buffer>;

/** Async on purpose: scrypt at these settings takes a few tenths of a second and must not block the event loop that serves every sign-in. */
async function derive(keys: StoreKeys, normalised: string, salt: Buffer, p: KdfParams): Promise<Buffer> {
  const pre = keyedHash(keys, 'answer', normalised);
  return scryptAsync(pre, salt, 32, { N: 2 ** p.logN, r: p.r, p: p.p, maxmem: 256 * 1024 * 1024 });
}

/** `scrypt$<logN>$<r>$<p>$<salt>$<hash>` (base64url). */
export async function hashAnswer(keys: StoreKeys, raw: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const hash = await derive(keys, normaliseAnswer(raw), salt, kdf);
  return `scrypt$${kdf.logN}$${kdf.r}$${kdf.p}$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

/** Constant-time check of an answer against a stored hash. A malformed stored value is a mismatch, never an exception. */
export async function verifyAnswer(keys: StoreKeys, raw: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, logN, r, p, salt, hash] = parts;
  const params = { logN: Number(logN), r: Number(r), p: Number(p) };
  if (![params.logN, params.r, params.p].every(Number.isInteger) || params.logN < 10 || params.logN > 20) return false;
  try {
    const got = await derive(keys, normaliseAnswer(raw), Buffer.from(salt as string, 'base64url'), params);
    return safeEqual(got.toString('base64url'), hash as string);
  } catch {
    return false;
  }
}

/**
 * Check every answer even after one is wrong, so the time taken does not say which one failed. Returns true only if ALL are right.
 * `answers` and `stored` must have the same length.
 */
export async function verifyAllAnswers(keys: StoreKeys, answers: readonly string[], stored: readonly string[]): Promise<boolean> {
  if (answers.length !== stored.length || answers.length === 0) return false;
  let ok = true;
  for (let i = 0; i < stored.length; i += 1) {
    if (!(await verifyAnswer(keys, answers[i] ?? '', stored[i] as string))) ok = false;
  }
  return ok;
}
