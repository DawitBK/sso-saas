/**
 * The Audit page's filters, as SQL. Pure: builds text and parameters and touches nothing, so every combination is tested without a
 * database. The platform administrator exclusions are part of the base clause and no filter can remove them (the same three
 * predicates the unfiltered list has always carried: its own email as actor or target, and its id inside the detail).
 */
import { PA_EMAILS_SQL, PA_IDS_SQL } from '../../auth/platform-admin.js';

export interface AuditFilterInput {
  /** Free text: matches the actor, the target or the action. */
  q?: string;
  /** An exact action (`user.disable`) or a family (`user.` matches everything that starts with it). */
  action?: string;
  /** The actor's email, exact (case-insensitive), or the literal `platform`. */
  actor?: string;
  /** YYYY-MM-DD, inclusive both ends, server time. */
  from?: string | null;
  to?: string | null;
}

export interface AuditFilter {
  where: string;
  params: unknown[];
}

const ACTION = /^[a-z_]+(\.[a-z_]+)*\.?$/;

export function buildAuditFilter(input: AuditFilterInput): AuditFilter {
  const params: unknown[] = [];
  const add = (v: unknown): string => {
    params.push(v);
    return `$${params.length}`;
  };
  const clauses: string[] = [
    `lower(actor_email) NOT IN ${PA_EMAILS_SQL}`,
    `lower(target) NOT IN ${PA_EMAILS_SQL}`,
    `coalesce(detail->>'userId', '') NOT IN ${PA_IDS_SQL}`,
  ];

  const q = (input.q ?? '').trim();
  if (q) {
    const p = add(q);
    clauses.push(`(actor_email ILIKE '%' || ${p} || '%' OR target ILIKE '%' || ${p} || '%' OR action ILIKE '%' || ${p} || '%')`);
  }

  const action = (input.action ?? '').trim().toLowerCase();
  if (action && ACTION.test(action)) {
    // A trailing dot is a family: `user.` -> LIKE 'user.%'. Underscores in an action are literal, so LIKE's `_` is escaped.
    clauses.push(action.endsWith('.') ? `action LIKE ${add(`${action.replace(/_/g, '\\_')}%`)}` : `action = ${add(action)}`);
  }

  const actor = (input.actor ?? '').trim();
  if (actor) clauses.push(`lower(actor_email) = ${add(actor.toLowerCase())}`);

  if (input.from) clauses.push(`created_at >= ${add(input.from)}::date`);
  if (input.to) clauses.push(`created_at < ${add(input.to)}::date + 1`);

  return { where: `WHERE ${clauses.join('\n  AND ')}`, params };
}
