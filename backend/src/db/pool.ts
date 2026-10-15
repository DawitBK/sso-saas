/**
 * Postgres connection pool for the IdP's own store (`edams_idp`).
 * Holds oidc-provider artifacts (grants, sessions, codes, tokens, interactions),
 * signing keys, local users/roles/groups, registered clients, and RP role mappings.
 */

import pg from 'pg';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';

/**
 * Explicit limits, not pg's defaults. This pool is on the critical path of
 * every single login on the platform: `findAccount` (auth/account.ts) queries
 * it on every token issuance, refresh, and /userinfo call, for every client.
 *
 * What the bare `{ connectionString }` form left unset, and why each matters:
 *  - `max` defaulted to 10. Low for the estate's only IdP.
 *  - `connectionTimeoutMillis` defaulted to 0 = wait forever. Under pool
 *    exhaustion, requests queued indefinitely instead of failing fast, so a
 *    slow query anywhere turned into an unbounded login hang.
 *  - `statement_timeout` was unset server-side for this pool, so a single
 *    pathological query (e.g. verifyAuditChain's full-table scan on a large
 *    idp_admin_audit) could hold a connection open with no ceiling.
 *  - `idleTimeoutMillis` default (10s) is fine, set explicitly for clarity.
 */
export const pool = new pg.Pool({
  connectionString: IDP_CONFIG.databaseUrl,
  max: IDP_CONFIG.db.poolMax,
  connectionTimeoutMillis: IDP_CONFIG.db.connectionTimeoutMs,
  idleTimeoutMillis: IDP_CONFIG.db.idleTimeoutMs,
  // Server-side ceiling on any single statement issued on this pool. Belt to
  // connectionTimeoutMillis's braces: that bounds how long we wait FOR a
  // connection, this bounds what a connection can do once it has one.
  statement_timeout: IDP_CONFIG.db.statementTimeoutMs,
});

pool.on('error', (err: Error) => {
  logger.error({ err }, '[idp:db] unexpected idle client error');
});

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params as never);
}
