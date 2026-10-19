/**
 * Licence storage: the `licenses` row (one per system) and the append-only `license_events` history (migration 025).
 * Plain SQL only; validation and the rules live in service.ts. Every write takes the caller's client so the row, its event and its audit entry
 * commit together or not at all.
 */
import type pg from 'pg';
import { pool } from '../db/pool.js';
import type { LicenseSystem } from './catalog.js';

export interface LicenseRecord {
  system: LicenseSystem;
  customer: string;
  expiresAt: string | null;
  graceDays: number;
  warnDays: number;
  maxUsers: number | null;
  modules: string[] | null;
  /** Deployment shapes this licence authorises: 'sso' and/or 'standalone'. */
  modes: string[];
  notes: string;
  version: number;
  createdAt: string;
  updatedAt: string;
  updatedBy: string;
}

export type LicenseAction = 'create' | 'update' | 'extend' | 'revoke';

export interface LicenseEventRecord {
  id: number;
  system: LicenseSystem;
  action: LicenseAction;
  actor: string;
  version: number;
  before: LicenseRecord | null;
  after: LicenseRecord | null;
  createdAt: string;
}

interface LicenseRow {
  system: LicenseSystem;
  customer: string;
  expires_at: Date | null;
  grace_days: number;
  warn_days: number;
  max_users: number | null;
  modules: string[] | null;
  modes: string[];
  notes: string;
  version: number;
  created_at: Date;
  updated_at: Date;
  updated_by: string;
}

type Queryable = Pick<pg.Pool | pg.PoolClient, 'query'>;

const COLUMNS = 'system, customer, expires_at, grace_days, warn_days, max_users, modules, modes, notes, version, created_at, updated_at, updated_by';

function toRecord(r: LicenseRow): LicenseRecord {
  return {
    system: r.system,
    customer: r.customer,
    expiresAt: r.expires_at ? r.expires_at.toISOString() : null,
    graceDays: r.grace_days,
    warnDays: r.warn_days,
    maxUsers: r.max_users,
    modules: r.modules,
    modes: r.modes,
    notes: r.notes,
    version: r.version,
    createdAt: r.created_at.toISOString(),
    updatedAt: r.updated_at.toISOString(),
    updatedBy: r.updated_by,
  };
}

export async function findLicense(system: LicenseSystem, db: Queryable = pool, forUpdate = false): Promise<LicenseRecord | null> {
  const { rows } = await db.query<LicenseRow>(`SELECT ${COLUMNS} FROM licenses WHERE system = $1${forUpdate ? ' FOR UPDATE' : ''}`, [system]);
  return rows[0] ? toRecord(rows[0]) : null;
}

export async function listLicenseRecords(db: Queryable = pool): Promise<LicenseRecord[]> {
  const { rows } = await db.query<LicenseRow>(`SELECT ${COLUMNS} FROM licenses ORDER BY system`);
  return rows.map(toRecord);
}

/** Highest version this system ever had, including a revoked licence's: the next licence continues from it, so versions never go backwards. */
export async function highestVersionEver(system: LicenseSystem, db: Queryable): Promise<number> {
  const { rows } = await db.query<{ v: number | null }>('SELECT MAX(version) AS v FROM license_events WHERE system = $1', [system]);
  return rows[0]?.v ?? 0;
}

export interface LicenseWrite {
  system: LicenseSystem;
  customer: string;
  expiresAt: string | null;
  graceDays: number;
  warnDays: number;
  maxUsers: number | null;
  modules: string[] | null;
  modes: string[];
  notes: string;
  version: number;
  actor: string;
}

export async function insertLicense(w: LicenseWrite, db: Queryable): Promise<LicenseRecord> {
  const { rows } = await db.query<LicenseRow>(
    `INSERT INTO licenses (system, customer, expires_at, grace_days, warn_days, max_users, modules, modes, notes, version, updated_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
     RETURNING ${COLUMNS}`,
    [w.system, w.customer, w.expiresAt, w.graceDays, w.warnDays, w.maxUsers, w.modules, w.modes, w.notes, w.version, w.actor],
  );
  return toRecord(rows[0]);
}

export async function updateLicense(w: LicenseWrite, db: Queryable): Promise<LicenseRecord> {
  const { rows } = await db.query<LicenseRow>(
    `UPDATE licenses
        SET customer = $2, expires_at = $3, grace_days = $4, warn_days = $5, max_users = $6, modules = $7, modes = $8, notes = $9,
            version = $10, updated_at = NOW(), updated_by = $11
      WHERE system = $1
      RETURNING ${COLUMNS}`,
    [w.system, w.customer, w.expiresAt, w.graceDays, w.warnDays, w.maxUsers, w.modules, w.modes, w.notes, w.version, w.actor],
  );
  return toRecord(rows[0]);
}

export async function deleteLicense(system: LicenseSystem, db: Queryable): Promise<void> {
  await db.query('DELETE FROM licenses WHERE system = $1', [system]);
}

export async function insertEvent(
  e: { system: LicenseSystem; action: LicenseAction; actor: string; version: number; before: LicenseRecord | null; after: LicenseRecord | null },
  db: Queryable,
): Promise<void> {
  await db.query(
    'INSERT INTO license_events (system, action, actor, version, before, after) VALUES ($1, $2, $3, $4, $5, $6)',
    [e.system, e.action, e.actor, e.version, e.before ? JSON.stringify(e.before) : null, e.after ? JSON.stringify(e.after) : null],
  );
}

export async function listEvents(system: LicenseSystem, limit = 20, db: Queryable = pool): Promise<LicenseEventRecord[]> {
  const { rows } = await db.query<{
    id: string; system: LicenseSystem; action: LicenseAction; actor: string; version: number;
    before: LicenseRecord | null; after: LicenseRecord | null; created_at: Date;
  }>(
    'SELECT id, system, action, actor, version, before, after, created_at FROM license_events WHERE system = $1 ORDER BY created_at DESC, id DESC LIMIT $2',
    [system, Math.max(1, Math.min(200, limit))],
  );
  return rows.map((r) => ({
    id: Number(r.id),
    system: r.system,
    action: r.action,
    actor: r.actor,
    version: r.version,
    before: r.before,
    after: r.after,
    createdAt: r.created_at.toISOString(),
  }));
}

/** Seats in use: every enabled account except the platform administrator (who is excluded from the count, contract section 6). */
export async function countSeatsUsed(db: Queryable = pool): Promise<number> {
  const { rows } = await db.query<{ n: string }>('SELECT COUNT(*) AS n FROM idp_users WHERE is_active AND NOT is_platform_admin');
  return Number(rows[0]?.n ?? 0);
}
