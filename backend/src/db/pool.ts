/**
 * Postgres connection pool for the IdP's own store (`edams_idp`).
 * Holds oidc-provider artifacts (grants, sessions, codes, tokens, interactions),
 * signing keys, local users/roles/groups, registered clients, and RP role mappings.
 */

import pg from 'pg';
import { IDP_CONFIG } from '../config.js';
import { logger } from '../logging/logger.js';

export const pool = new pg.Pool({ connectionString: IDP_CONFIG.databaseUrl });

pool.on('error', (err: Error) => {
  logger.error({ err }, '[idp:db] unexpected idle client error');
});

export async function query<T extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params?: unknown[],
): Promise<pg.QueryResult<T>> {
  return pool.query<T>(text, params as never);
}
