/**
 * The Sign-ins page's filters, as SQL (shared by the list, its count and the CSV export). Pure, so it is tested without a database.
 * The platform administrator's own attempts are never recorded (auth/platform-admin.ts); the clause below also keeps any row that
 * names it out of the result, whatever the filters say.
 */
export interface LoginFilterInput {
  /** true = only successful, false = only failed, null = both. */
  success?: boolean | null;
  /** Matches the email or the address. */
  q?: string;
  /** An exact reason code (invalid_credentials, locked, mfa_failed, mfa_recovery_used ...). */
  reason?: string;
  /** YYYY-MM-DD, inclusive both ends, server time. */
  from?: string | null;
  to?: string | null;
}

export interface LoginFilter {
  where: string;
  params: unknown[];
}

const REASON = /^[a-z_]{1,40}$/;

/** Selects over `idp_login_events e LEFT JOIN idp_users u ON lower(u.email) = e.email`. */
export function buildLoginFilter(input: LoginFilterInput): LoginFilter {
  const params: unknown[] = [];
  const add = (v: unknown): string => {
    params.push(v);
    return `$${params.length}`;
  };
  const clauses: string[] = ['(u.id IS NULL OR NOT u.is_platform_admin)'];
  if (input.success === true || input.success === false) clauses.push(`e.success = ${add(input.success)}`);
  const q = (input.q ?? '').trim();
  if (q) {
    const p = add(q);
    clauses.push(`(e.email ILIKE '%' || ${p} || '%' OR e.ip ILIKE '%' || ${p} || '%')`);
  }
  const reason = (input.reason ?? '').trim();
  if (reason && REASON.test(reason)) clauses.push(`e.reason = ${add(reason)}`);
  if (input.from) clauses.push(`e.created_at >= ${add(input.from)}::date`);
  if (input.to) clauses.push(`e.created_at < ${add(input.to)}::date + 1`);
  return { where: `WHERE ${clauses.join('\n  AND ')}`, params };
}
