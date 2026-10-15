/**
 * Group-membership counts, in one place (P2-2 / P2-9 item 6).
 *
 * `SELECT group_dn, COUNT(*) AS count FROM idp_user_groups GROUP BY group_dn`
 * existed verbatim in both admin/access.ts (the EJS/JSON admin console) and
 * api/v1/admin.router.ts (the versioned API the Next.js console calls), together
 * with the Map-building that follows it. Duplication is how the two consoles
 * drift: the two copies had ALREADY diverged on the value type — one returned the
 * count as a string, the other coerced it to a number, so the same endpoint
 * described the same data two different ways depending on which door you came
 * through.
 *
 * This is the first extraction of P2-2's larger de-duplication, not the whole of
 * it: the two routers still duplicate their user, session and key handlers. That
 * is a real refactor with a real regression surface and it wants the integration
 * tests P2-1 flags as missing before it is attempted — starting it halfway would
 * leave three sources of truth instead of two.
 */

import { pool } from '../../db/pool.js';

export interface GroupWithMemberCount {
  dn: string;
  /** Number of users in this group. A number, uniformly, for both consumers. */
  memberCount: number;
}

/** DN → member count, for every group that has at least one member. */
export async function groupMemberCounts(): Promise<Map<string, number>> {
  const { rows } = await pool.query<{ group_dn: string; count: string }>(
    'SELECT g.group_dn, COUNT(*) AS count FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id WHERE NOT u.is_platform_admin GROUP BY g.group_dn',
  );
  return new Map(rows.map((r) => [r.group_dn, Number(r.count)]));
}

/**
 * Decorate a list of group DNs with their member counts. Groups with no members
 * are absent from the aggregate above, so they get 0 rather than being dropped.
 */
export async function withMemberCounts(dns: string[]): Promise<GroupWithMemberCount[]> {
  const counts = await groupMemberCounts();
  return dns.map((dn) => ({ dn, memberCount: counts.get(dn) ?? 0 }));
}
