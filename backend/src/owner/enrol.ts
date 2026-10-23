/**
 * The logic behind the terminal tools (`npm run owner:enroll | owner:recover | owner:change-email | owner:status | owner:unlock`), kept out of the scripts
 * so it can be tested. The scripts own the terminal (hidden input, nothing from argv, env or pipes); this module never prompts and never prints.
 *
 * Owner-only tools stay as TypeScript source run with tsx, like the platform-vault tool: they are NOT part of the compiled production package.
 */
import path from 'node:path';
import { pool } from '../db/pool.js';
import { ownerAudit } from './audit.js';
import { smtpFingerprint } from './mailer.js';
import { answerProblem, hashAnswer } from './questions.js';
import { RECOVERY_CODE_COUNT, SECURITY_QUESTION_COUNT } from './policy.js';
import { generateRecoveryCodes } from './recovery.js';
import type { StoreKeys } from './seal.js';
import { writeStore, type OwnerStoreDoc } from './store.js';

export const DEFAULT_QUESTION_PROMPTS = ['What is your best movie?', 'What is your best TV series?', 'Your Legion question'] as const;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export const emailProblem = (address: string): string | null => (address.length <= 254 && EMAIL_RE.test(address) ? null : 'That does not look like an email address.');

/** True if `file` lies inside `root` (the repository): a key file there could be committed or shipped by accident. */
export function isInside(file: string, root: string): boolean {
  const rel = path.relative(path.resolve(root), path.resolve(file));
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** The one platform administrator's account id, or a reason there is not exactly one. */
export async function findOwnerAccountId(): Promise<{ id: string } | { problem: string }> {
  const { rows } = await pool.query<{ id: string }>('SELECT id FROM idp_users WHERE is_platform_admin');
  if (rows.length === 0) return { problem: 'No account is marked as the platform administrator in this database.' };
  if (rows.length > 1) return { problem: 'More than one account is marked as the platform administrator; owner verification needs exactly one.' };
  return { id: (rows[0] as { id: string }).id };
}

export interface EnrolInput {
  keys: StoreKeys;
  accountId: string;
  questions: Array<{ prompt: string; answer: string }>;
  emailAddress: string;
  /** The authenticator secret. Required unless `authenticator` is false, and then it must not be given: nothing is stored for an authenticator that is not used. */
  totpSecret?: string;
  /** Whether this enrolment includes the phone authenticator (default true). Recorded in the sealed store; verification demands exactly these factors. */
  authenticator?: boolean;
}

/** Validate, hash and store. Returns the recovery codes: shown ONCE by the caller and never kept. Replaces any earlier enrolment. */
export async function enrolOwner(input: EnrolInput): Promise<{ codes: string[] }> {
  const withAuthenticator = input.authenticator !== false;
  if (withAuthenticator && !input.totpSecret) throw new Error('An authenticator secret is needed for an enrolment that uses the authenticator.');
  if (!withAuthenticator && input.totpSecret) throw new Error('An enrolment without the authenticator must not carry an authenticator secret.');
  if (input.questions.length !== SECURITY_QUESTION_COUNT) throw new Error(`Exactly ${SECURITY_QUESTION_COUNT} questions are needed.`);
  for (const q of input.questions) {
    const problem = answerProblem(q.answer);
    if (problem) throw new Error(problem);
    if (!q.prompt.trim() || q.prompt.length > 200) throw new Error('A question needs a short prompt.');
  }
  const bad = emailProblem(input.emailAddress);
  if (bad) throw new Error(bad);
  const questions: OwnerStoreDoc['questions'] = [];
  for (const q of input.questions) questions.push({ prompt: q.prompt.trim(), hash: await hashAnswer(input.keys, q.answer) });
  const { codes, records } = generateRecoveryCodes(input.keys, RECOVERY_CODE_COUNT);
  const now = new Date().toISOString();
  await writeStore(input.keys, {
    v: 1,
    accountId: input.accountId,
    questions,
    email: { address: input.emailAddress.trim(), smtpFingerprint: smtpFingerprint() },
    ...(withAuthenticator ? { totp: { secret: input.totpSecret as string } } : {}),
    factors: { authenticator: withAuthenticator },
    recoveryCodes: records,
    createdAt: now,
    updatedAt: now,
  });
  await ownerAudit('enrolled', 'ok', { detail: { questions: questions.length, recoveryCodes: codes.length, authenticator: withAuthenticator ? 'used' : 'not used' } });
  return { codes };
}

/** Change only the mailbox address (and re-record the current mail relay). Everything else in the store is kept. */
export async function changeEmail(keys: StoreKeys, doc: OwnerStoreDoc, newAddress: string): Promise<void> {
  const bad = emailProblem(newAddress);
  if (bad) throw new Error(bad);
  await writeStoreKeepingUsedCodes(keys, { ...doc, email: { address: newAddress.trim(), smtpFingerprint: smtpFingerprint() }, updatedAt: new Date().toISOString() });
  await ownerAudit('email_changed', 'ok');
}

/** Like writeStore, but the used-recovery-code list is kept (the codes are unchanged). */
async function writeStoreKeepingUsedCodes(keys: StoreKeys, doc: OwnerStoreDoc): Promise<void> {
  const { rows } = await pool.query<{ code_id: string; used_at: Date }>('SELECT code_id, used_at FROM owner_recovery_codes_used');
  await writeStore(keys, doc);
  for (const r of rows) await pool.query('INSERT INTO owner_recovery_codes_used (code_id, used_at) VALUES ($1, $2) ON CONFLICT DO NOTHING', [r.code_id, r.used_at]);
}
