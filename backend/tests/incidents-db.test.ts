/**
 * The incident table against a REAL Postgres (migration 028): append-only triggers, the hash chain, the membership scan and the chain-head collector.
 *
 * It always runs, on every machine, so the Jest totals (and docs/TEST_STATUS.md, which CI diffs) never depend on where the suite ran. It makes its
 * own SCRATCH database (idp_incidents_scratch_<pid>_<random>) on the same server DATABASE_URL points at, applies every migration to it and drops it
 * afterwards, so it never touches idp, idpprod or any shared database. The role needs CREATEDB (CI's and the developer's `postgres` have it).
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

// A jest.mock factory may only touch variables named mock*: the scratch pool is created in beforeAll, and the pool the code under test
// imports forwards to it.
const mockScratch: { pool: pg.Pool | null } = { pool: null };

jest.mock('../src/db/pool.js', () => ({
  pool: new Proxy({}, {
    get: (_t, prop) => {
      const target = mockScratch.pool as unknown as Record<string | symbol, unknown> | null;
      if (!target) throw new Error('scratch pool is not ready (beforeAll has not run)');
      const value = target[prop];
      return typeof value === 'function' ? (value as (...a: unknown[]) => unknown).bind(target) : value;
    },
  }),
}));

import { pool } from '../src/db/pool.js';
import { recordIncident, verifyIncidentChain, listIncidents } from '../src/ops/incidents.js';
import { scanPrivilegeChanges } from '../src/ops/privilegeWatch.js';
import { collectChainHead } from '../src/ops/chainHead.js';
import { IDP_CONFIG } from '../src/config.js';
import type { SecurityEvent } from '../src/ops/securityEvents.js';

const scratchName = `idp_incidents_scratch_${process.pid}_${crypto.randomBytes(4).toString('hex')}`;
const scratchUrl = (() => { const u = new URL(IDP_CONFIG.databaseUrl); u.pathname = `/${scratchName}`; return u.toString(); })();
const MIGRATIONS = path.join(__dirname, '..', 'migrations');

const ev = (kind = 'owner_op_denied'): SecurityEvent => ({ kind, severity: 'critical', actor: { userId: 'u1' }, operation: 'op', detail: { n: 1 }, at: new Date().toISOString() });

describe('security_incidents (real Postgres, scratch database)', () => {
  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
    await admin.connect();
    try { await admin.query(`CREATE DATABASE "${scratchName}"`); } finally { await admin.end(); }
    mockScratch.pool = new pg.Pool({ connectionString: scratchUrl, max: 4 });
    // the same files `npm run db:migrate` applies, in the same order (the .down.sql rollbacks excluded)
    const files = fs.readdirSync(MIGRATIONS).filter((f) => f.endsWith('.sql') && !f.endsWith('.down.sql')).sort();
    for (const f of files) await pool.query(fs.readFileSync(path.join(MIGRATIONS, f), 'utf8'));
  }, 60_000);
  afterAll(async () => {
    await mockScratch.pool?.end();
    mockScratch.pool = null;
    const admin = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
    await admin.connect();
    try { await admin.query(`DROP DATABASE IF EXISTS "${scratchName}" WITH (FORCE)`); } finally { await admin.end(); }
  }, 30_000);

  it('appends a verifying chain', async () => {
    const a = await recordIncident(ev(), { decision: 'alert' });
    const b = await recordIncident(ev('audit_chain_broken'), { decision: 'lock', locked: true });
    expect(a.sequenceNumber).toBe('1');
    expect(b.sequenceNumber).toBe('2');
    const v = await verifyIncidentChain();
    expect(v).toMatchObject({ valid: true, checked: 2, headSequence: '2', headHash: b.entryHash });
    const list = await listIncidents();
    expect(list.total).toBe(2);
    expect(list.items[0]!.kind).toBe('audit_chain_broken');
  });

  it('refuses UPDATE, DELETE and TRUNCATE (append-only triggers)', async () => {
    await expect(pool.query("UPDATE security_incidents SET kind = 'x'")).rejects.toThrow(/append-only/);
    await expect(pool.query('DELETE FROM security_incidents')).rejects.toThrow(/append-only/);
    await expect(pool.query('TRUNCATE security_incidents')).rejects.toThrow(/append-only/);
  });

  it('still finds an edited row when the triggers were switched off (hash break), and a removed row (linkage break)', async () => {
    await recordIncident(ev(), { decision: 'alert' });
    await pool.query('ALTER TABLE security_incidents DISABLE TRIGGER USER');
    try {
      await pool.query("UPDATE security_incidents SET detail = '{\"n\": 999}' WHERE sequence_number = 2");
      expect(await verifyIncidentChain()).toMatchObject({ valid: false, brokenAt: '2' });
      await pool.query("UPDATE security_incidents SET detail = '{\"n\": 1}' WHERE sequence_number = 2");
      expect((await verifyIncidentChain()).valid).toBe(true);
      await pool.query('DELETE FROM security_incidents WHERE sequence_number = 2');
      expect(await verifyIncidentChain()).toMatchObject({ valid: false, brokenAt: '3' });
    } finally {
      await pool.query('ALTER TABLE security_incidents ENABLE TRIGGER USER');
    }
  });

  it('serialises concurrent writers without forking the chain', async () => {
    await pool.query('ALTER TABLE security_incidents DISABLE TRIGGER USER');
    await pool.query('DELETE FROM security_incidents');
    await pool.query('ALTER TABLE security_incidents ENABLE TRIGGER USER');
    await Promise.all(Array.from({ length: 8 }, () => recordIncident(ev(), {})));
    expect(await verifyIncidentChain()).toMatchObject({ valid: true, checked: 8 });
  });

  it('the membership scan: baseline, then an unexplained addition is reported once', async () => {
    const { rows: u } = await pool.query<{ id: string }>(`INSERT INTO idp_users (email, given_name, family_name) VALUES ('scan.test@example.test', 'Scan', 'Test') ON CONFLICT (email) DO UPDATE SET given_name = 'Scan' RETURNING id`);
    await pool.query("DELETE FROM security_state WHERE key = 'admin_group_snapshot'");
    expect(await scanPrivilegeChanges()).toEqual([]); // baseline
    await pool.query('INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [u[0].id, IDP_CONFIG.adminGroup]);
    const found = await scanPrivilegeChanges();
    expect(found).toEqual([{ outcome: 'unexplained', direction: 'added', userId: u[0].id }]);
    expect(await scanPrivilegeChanges()).toEqual([]); // not raised twice
    await pool.query('DELETE FROM idp_user_groups WHERE user_id = $1 AND group_dn = $2', [u[0].id, IDP_CONFIG.adminGroup]);
    expect(await scanPrivilegeChanges()).toEqual([{ outcome: 'unexplained', direction: 'removed', userId: u[0].id }]);
  });

  it('the chain head reports counts and hashes, and the hash at a given audit sequence', async () => {
    const head = await collectChainHead('1');
    expect(head.incidents.valid).toBe(true);
    expect(head.incidents.count).toBe(8);
    expect(head.audit.count).toBeGreaterThanOrEqual(0);
    expect(head.at).toEqual({ sequence: '1', hash: head.at!.hash });
    expect(Object.keys(head).sort()).toEqual(['at', 'audit', 'checkedAt', 'incidents']);
  });
});
