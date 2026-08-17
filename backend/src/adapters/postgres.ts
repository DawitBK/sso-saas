/**
 * PostgreSQL adapter for oidc-provider (Panva), backed by the single
 * `oidc_artifacts` table. Persists every model the provider uses — including
 * Session (the SSO backbone) — so single-sign-on and refresh survive restarts
 * and work across multiple instances.
 *
 * Implements the oidc-provider Adapter contract:
 *   upsert / find / findByUserCode / findByUid / consume / destroy / revokeByGrantId
 *
 * (Schema lives in migrations/001_init.sql.)
 */

import type { Adapter, AdapterPayload } from 'oidc-provider';
import { pool } from '../db/pool.js';

export class PostgresAdapter implements Adapter {
  constructor(private readonly name: string) {}

  async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
    const expiresAt = expiresIn ? new Date(Date.now() + expiresIn * 1000) : null;
    await pool.query(
      `INSERT INTO oidc_artifacts (id, kind, payload, grant_id, user_code, uid, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (kind, id)
       DO UPDATE SET payload = $3, grant_id = $4, user_code = $5, uid = $6, expires_at = $7`,
      [
        id,
        this.name,
        JSON.stringify(payload),
        payload.grantId ?? null,
        payload.userCode ?? null,
        payload.uid ?? null,
        expiresAt,
      ],
    );
  }

  private static hydrate(row: { payload: AdapterPayload; consumed_at: Date | null } | undefined): AdapterPayload | undefined {
    if (!row) return undefined;
    const payload = row.payload;
    if (row.consumed_at) {
      payload.consumed = Math.floor(new Date(row.consumed_at).getTime() / 1000);
    }
    return payload;
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const { rows } = await pool.query(
      `SELECT payload, consumed_at FROM oidc_artifacts
       WHERE kind = $1 AND id = $2 AND (expires_at IS NULL OR expires_at > NOW())`,
      [this.name, id],
    );
    return PostgresAdapter.hydrate(rows[0]);
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const { rows } = await pool.query(
      `SELECT payload, consumed_at FROM oidc_artifacts
       WHERE kind = $1 AND user_code = $2 AND (expires_at IS NULL OR expires_at > NOW())`,
      [this.name, userCode],
    );
    return PostgresAdapter.hydrate(rows[0]);
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const { rows } = await pool.query(
      `SELECT payload, consumed_at FROM oidc_artifacts
       WHERE kind = $1 AND uid = $2 AND (expires_at IS NULL OR expires_at > NOW())`,
      [this.name, uid],
    );
    return PostgresAdapter.hydrate(rows[0]);
  }

  async consume(id: string): Promise<void> {
    await pool.query(
      `UPDATE oidc_artifacts SET consumed_at = NOW() WHERE kind = $1 AND id = $2`,
      [this.name, id],
    );
  }

  async destroy(id: string): Promise<void> {
    await pool.query(`DELETE FROM oidc_artifacts WHERE kind = $1 AND id = $2`, [this.name, id]);
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    await pool.query(`DELETE FROM oidc_artifacts WHERE grant_id = $1`, [grantId]);
  }
}

/** Factory oidc-provider calls with each model name. */
export const postgresAdapterFactory = (name: string): PostgresAdapter => new PostgresAdapter(name);
