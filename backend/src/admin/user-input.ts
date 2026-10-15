/**
 * The rules for the text an administrator (or a directory sync) puts into a user record, in one place.
 *
 * The same numbers are enforced three times and must never drift apart: here (the routes refuse with a message naming the field), in the
 * database (migration 023 gives `idp_users` matching CHECK constraints, so a script or a future code path that skips this module cannot store
 * what the console would refuse), and in the browser (the create-user form reads `limits` from `GET /admin/role-catalog`, so its inputs stop at
 * the same length instead of carrying their own copy of the number). `tests/user-input.test.ts` reads the migration and fails if they differ.
 */

export const USER_LIMITS = {
  /** RFC 5321: a mailbox address is at most 254 characters. */
  email: 254,
  /** First name and last name, each. */
  name: 100,
} as const;

export interface FieldProblem {
  field: string;
  message: string;
}

const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// eslint-disable-next-line no-control-regex -- the point is to refuse control characters (NUL cannot be stored at all)
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/** Trim and cut to the stored length (by characters, not bytes). For values we do not choose, such as a name read from Active Directory: never refuse a sign-in over a long name. */
export function clipName(value: unknown): string {
  const text = typeof value === 'string' ? value.trim() : '';
  return Array.from(text).slice(0, USER_LIMITS.name).join('');
}

/** What is wrong with the identity fields of a new user (already trimmed; the email already lower-cased). Empty when nothing is. */
export function identityProblems(input: { email: string; givenName: string; familyName: string }): FieldProblem[] {
  const problems: FieldProblem[] = [];
  if (!input.email) {
    problems.push({ field: 'email', message: 'Enter an email address.' });
  } else if (input.email.length > USER_LIMITS.email) {
    problems.push({ field: 'email', message: `The email address can be at most ${USER_LIMITS.email} characters.` });
  } else if (!EMAIL_SHAPE.test(input.email) || CONTROL_CHARACTERS.test(input.email)) {
    problems.push({ field: 'email', message: 'Enter a valid email address, such as person@examplecorp.com.' });
  }
  for (const [field, label, value] of [
    ['given_name', 'First name', input.givenName],
    ['family_name', 'Last name', input.familyName],
  ] as const) {
    if (Array.from(value).length > USER_LIMITS.name) problems.push({ field, message: `${label} can be at most ${USER_LIMITS.name} characters.` });
    else if (CONTROL_CHARACTERS.test(value)) problems.push({ field, message: `${label} contains a character that is not allowed.` });
  }
  return problems;
}

/** An office id from a request body: null when none was given, the id when it is a positive whole number, 'bad' otherwise. */
export function parseOfficeId(raw: unknown): number | null | 'bad' {
  if (raw === undefined || raw === null || raw === '') return null;
  const n = typeof raw === 'number' ? raw : typeof raw === 'string' && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : NaN;
  return Number.isSafeInteger(n) && n > 0 ? n : 'bad';
}
