/**
 * Licence changes: save (create or update), extend and revoke (docs/operations/PLATFORM-LICENSING.md sections 2 and 5).
 *
 * Every change runs in ONE transaction: the `licenses` row, its `license_events` row and its entry in the tamper-evident admin audit chain
 * (writeAudit joins the same client) commit together or not at all, under a per-system advisory lock so two administrators cannot interleave.
 * `version` is TIME-ORDERED (version.ts: seconds since 2026-01-01 UTC) and strictly higher than anything this system ever had, even across a
 * revoke and a new licence, because a consumer ignores any token whose version is lower than the one it holds. The time base is what makes a
 * console save beat an earlier offline-signed licence (and the reverse): the latest issue wins, whichever channel made it.
 */
import type { Request } from 'express';
import { pool } from '../db/pool.js';
import { writeAudit } from '../admin/audit.js';
import type { LicenseSystem } from './catalog.js';
import {
  deleteLicense, findLicense, highestVersionEver, insertEvent, insertLicense, updateLicense,
  type LicenseAction, type LicenseRecord,
} from './repository.js';
import { extendedExpiry, parseExpiry, validateExtendInput, validateLicenseInput, type FieldProblem } from './validation.js';
import { invalidateOwnLicense } from './status.js';
import { nextLicenseVersion } from './version.js';

/** A refusal the route turns into a typed answer: HTTP status, error code, a message an administrator can read, and per-field details. */
export class LicenseError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: FieldProblem[],
  ) {
    super(message);
    this.name = 'LicenseError';
  }
}

export interface Actor {
  /** The signed-in administrator's address (writeAudit makes the platform administrator anonymous itself). */
  email: string;
  /** What is stored in `updated_by` and the event: 'platform' for the platform administrator, otherwise the address. */
  label: string;
}

const notFound = (system: LicenseSystem): LicenseError => new LicenseError(404, 'ERR-LICENSE-NOT-FOUND', `There is no licence for ${system.toUpperCase()}.`);

async function inTransaction<T>(system: LicenseSystem, work: (client: import('pg').PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [`license:${system}`]);
    const out = await work(client);
    await client.query('COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function nextVersion(system: LicenseSystem, existing: LicenseRecord | null, client: import('pg').PoolClient): Promise<number> {
  // max(highest ever + 1, seconds since the epoch): never goes backwards (clock stepped back, same second, a revoke in between) and always
  // beats a licence issued earlier by any channel.
  return nextLicenseVersion(Math.max(existing?.version ?? 0, await highestVersionEver(system, client)), Date.now());
}

async function record(
  req: Request,
  actor: Actor,
  action: LicenseAction,
  system: LicenseSystem,
  before: LicenseRecord | null,
  after: LicenseRecord | null,
  version: number,
  client: import('pg').PoolClient,
): Promise<void> {
  await insertEvent({ system, action, actor: actor.label, version, before, after }, client);
  await writeAudit(req, actor.email, `license.${action}`, system, { before, after, version }, client);
}

/** Create the licence for `system`, or update the one that exists (fields left out keep their stored value). */
export async function saveLicense(req: Request, actor: Actor, system: LicenseSystem, body: unknown): Promise<{ license: LicenseRecord; action: 'create' | 'update' }> {
  const result = await inTransaction(system, async (client) => {
    const existing = await findLicense(system, client, true);
    const checked = validateLicenseInput(system, body, existing);
    if (!checked.ok) throw new LicenseError(400, 'ERR-VALIDATION-FAILED', checked.details[0].message, checked.details);
    const version = await nextVersion(system, existing, client);
    const write = { system, ...checked.value, version, actor: actor.label };
    const license = existing ? await updateLicense(write, client) : await insertLicense(write, client);
    const action = existing ? 'update' : 'create';
    await record(req, actor, action, system, existing, license, version, client);
    return { license, action } as const;
  });
  if (system === 'sso') invalidateOwnLicense();
  return result;
}

/** Push the expiry later: `{ days }` counts from the later of the current expiry and now; `{ expiresAt }` sets it. */
export async function extendLicense(req: Request, actor: Actor, system: LicenseSystem, body: unknown, nowMs: number = Date.now()): Promise<LicenseRecord> {
  const license = await inTransaction(system, async (client) => {
    const existing = await findLicense(system, client, true);
    if (!existing) throw notFound(system);
    const checked = validateExtendInput(body);
    if (!checked.ok) throw new LicenseError(400, 'ERR-VALIDATION-FAILED', checked.details[0].message, checked.details);
    if (existing.expiresAt === null && 'days' in checked.value) {
      throw new LicenseError(409, 'ERR-LICENSE-PERPETUAL', 'This licence never expires, so there is nothing to extend. Set an expiry date instead.');
    }
    const expiresAt = 'days' in checked.value ? extendedExpiry(existing.expiresAt as string, checked.value.days, nowMs) : checked.value.expiresAt;
    // The same limits as a save (the result of "+3650 days" can leave the supported range).
    const range = parseExpiry(expiresAt);
    if (!range.ok) throw new LicenseError(400, 'ERR-VALIDATION-FAILED', range.message, [{ field: 'expiresAt', message: range.message }]);
    const version = await nextVersion(system, existing, client);
    const updated = await updateLicense(
      { system, customer: existing.customer, expiresAt, graceDays: existing.graceDays, warnDays: existing.warnDays, maxUsers: existing.maxUsers, modules: existing.modules, modes: existing.modes, notes: existing.notes, version, actor: actor.label },
      client,
    );
    await record(req, actor, 'extend', system, existing, updated, version, client);
    return updated;
  });
  if (system === 'sso') invalidateOwnLicense();
  return license;
}

/** Delete the active record (the system returns to `unconfigured`); the event and the audit entry stay. */
export async function revokeLicense(req: Request, actor: Actor, system: LicenseSystem): Promise<void> {
  await inTransaction(system, async (client) => {
    const existing = await findLicense(system, client, true);
    if (!existing) throw notFound(system);
    const version = await nextVersion(system, existing, client);
    await deleteLicense(system, client);
    await record(req, actor, 'revoke', system, existing, null, version, client);
  });
  if (system === 'sso') invalidateOwnLicense();
}
