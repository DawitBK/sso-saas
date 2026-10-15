/**
 * The admin audit chain's verifier and the acknowledgement of a known break (admin/audit.ts).
 *
 * The chain is built by the real writeAudit against an in-memory stand-in for the three tables it touches, so what is verified is exactly
 * what production writes. Proves: a clean chain verifies; one edited row is ONE hash break (not a cascade down the chain); a removed row is a
 * linkage break; a chain cut short at the end is a tail break that cannot be acknowledged; an acknowledgement covers exactly that break and
 * is itself an entry in the chain; a row altered again after it was acknowledged is a new, open break; and the refusals (not reported, already
 * acknowledged, too-short reason, kinds that cannot be acknowledged).
 */
type Row = {
  sequence_number: string;
  previous_hash: string | null;
  entry_hash: string;
  actor_email: string;
  action: string;
  target: string;
  detail: unknown;
  ip: string;
  user_agent: string;
  created_at: Date;
  hash_version: number;
};
type Ack = {
  sequence_number: string;
  kind: string;
  entry_hash: string;
  previous_hash: string | null;
  row_fingerprint: string;
  reason: string;
  acknowledged_by: string;
  acknowledged_at: Date;
};

const db = {
  rows: [] as Row[],
  anchor: null as { sequence_number: string; entry_hash: string } | null,
  acks: [] as Ack[],
  seq: 0,
};

function run(sql: string, params: unknown[] = []): { rows: unknown[] } {
  const q = sql.replace(/\s+/g, ' ').trim();
  if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(q) || q.startsWith('SELECT pg_advisory_xact_lock')) return { rows: [] };
  if (q.startsWith('SELECT entry_hash FROM idp_admin_audit ORDER BY sequence_number DESC LIMIT 1')) {
    const last = [...db.rows].sort((a, b) => Number(b.sequence_number) - Number(a.sequence_number))[0];
    return { rows: last ? [{ entry_hash: last.entry_hash }] : [] };
  }
  if (q.startsWith('SELECT nextval')) return { rows: [{ sequence_number: String(++db.seq) }] };
  if (q.startsWith('INSERT INTO idp_admin_audit_anchor')) {
    db.anchor = { sequence_number: String(params[0]), entry_hash: String(params[1]) };
    return { rows: [] };
  }
  if (q.startsWith('INSERT INTO idp_admin_audit ')) {
    const [actor, action, target, detail, ip, ua, seq, prev, hash, createdAt, version] = params as [string, string, string, string, string, string, string, string | null, string, Date, number];
    db.rows.push({ sequence_number: String(seq), previous_hash: prev, entry_hash: hash, actor_email: actor, action, target, detail: JSON.parse(detail), ip, user_agent: ua, created_at: createdAt, hash_version: version });
    return { rows: [] };
  }
  if (q.startsWith('SELECT sequence_number, entry_hash FROM idp_admin_audit_anchor')) return { rows: db.anchor ? [db.anchor] : [] };
  if (q.includes('FROM idp_admin_audit WHERE sequence_number >')) {
    const [after, limit] = params as [string, number];
    const rows = db.rows
      .filter((r) => BigInt(r.sequence_number) > BigInt(after))
      .sort((a, b) => Number(a.sequence_number) - Number(b.sequence_number))
      .slice(0, limit);
    return { rows: rows.map((r) => ({ ...r })) };
  }
  if (q.includes('FROM idp_audit_chain_acknowledgements')) return { rows: db.acks.map((a) => ({ ...a })) };
  if (q.startsWith('INSERT INTO idp_audit_chain_acknowledgements')) {
    const [seq, kind, entryHash, prev, fp, reason, by] = params as [string, string, string, string | null, string, string, string];
    db.acks = db.acks.filter((a) => !(a.sequence_number === String(seq) && a.kind === kind));
    db.acks.push({ sequence_number: String(seq), kind, entry_hash: entryHash, previous_hash: prev, row_fingerprint: fp, reason, acknowledged_by: by, acknowledged_at: new Date() });
    return { rows: [] };
  }
  throw new Error(`unexpected SQL in audit-chain test: ${q.slice(0, 80)}`);
}

jest.mock('../src/db/pool.js', () => {
  const query = async (sql: string, params?: unknown[]) => run(sql, params);
  return { pool: { query, connect: async () => ({ query, release: () => undefined }) } };
});
jest.mock('../src/auth/platform-admin.js', () => ({
  PA_EMAILS_SQL: '(SELECT 1)',
  PA_IDS_SQL: '(SELECT 1)',
  isPlatformAdminEmail: async (e: string) => e === 'root@platform.test',
}));

import type { Request } from 'express';
import { ACKNOWLEDGEABLE_KINDS, ChainAcknowledgementError, acknowledgeChainBreak, verifyAuditChain, writeAudit } from '../src/admin/audit.js';

const req = { get: () => 'jest', ip: '10.0.0.1', headers: {}, socket: { remoteAddress: '10.0.0.1' } } as unknown as Request;
const REASON = 'Restored from the 2026-09-02 backup; the gap is known and was reviewed.';

async function seed(n = 5): Promise<void> {
  db.rows = [];
  db.anchor = null;
  db.acks = [];
  db.seq = 0;
  for (let i = 1; i <= n; i++) await writeAudit(req, 'admin@example.test', `test.action${i}`, `target-${i}`, { n: i });
}

const rowAt = (seq: number): Row => db.rows.find((r) => r.sequence_number === String(seq))!;

beforeEach(async () => {
  await seed();
});

describe('verifyAuditChain', () => {
  it('verifies a clean chain, both ends pinned to the anchor', async () => {
    const r = await verifyAuditChain();
    expect(r.valid).toBe(true);
    expect(r.checked).toBe(5);
    expect(r.breaks).toEqual([]);
    expect(r.openBreaks).toBe(0);
    expect(r.message).toMatch(/both ends pinned/);
  });

  it('reports an empty chain without an anchor as fine, and an empty table with an anchor as emptied', async () => {
    db.rows = [];
    db.anchor = null;
    expect((await verifyAuditChain()).valid).toBe(true);
    db.anchor = { sequence_number: '5', entry_hash: 'x' };
    const r = await verifyAuditChain();
    expect(r.valid).toBe(false);
    expect(r.breaks[0].kind).toBe('empty');
    expect(r.breaks[0].acknowledgeable).toBe(false);
  });

  it('one edited row is ONE hash break, not a cascade down the rest of the chain', async () => {
    (rowAt(3).detail as { n: number }).n = 999;
    const r = await verifyAuditChain();
    expect(r.valid).toBe(false);
    expect(r.breaks.map((b) => [b.sequenceNumber, b.kind])).toEqual([['3', 'hash']]);
    expect(r.brokenAtSequence).toBe('3');
    expect(r.breaks[0].acknowledgeable).toBe(true);
  });

  it('a removed row is a linkage break at the row after it, and every break is listed, not just the first', async () => {
    (rowAt(2).detail as { n: number }).n = 222;
    db.rows = db.rows.filter((r) => r.sequence_number !== '4');
    const r = await verifyAuditChain();
    expect(r.breaks.map((b) => `${b.sequenceNumber}:${b.kind}`).sort()).toEqual(['2:hash', '5:linkage']);
    expect(r.openBreaks).toBe(2);
  });

  it('a chain cut short at the end is a tail break and cannot be acknowledged', async () => {
    db.rows = db.rows.filter((r) => r.sequence_number !== '5');
    const r = await verifyAuditChain();
    expect(r.valid).toBe(false);
    expect(r.breaks).toHaveLength(1);
    expect(r.breaks[0]).toMatchObject({ kind: 'tail', acknowledgeable: false });
  });

  it('rows deleted from the start leave a head break', async () => {
    db.rows = db.rows.filter((r) => r.sequence_number !== '1');
    const r = await verifyAuditChain();
    expect(r.breaks.map((b) => b.kind)).toEqual(['head']);
    expect(ACKNOWLEDGEABLE_KINDS).toContain('head');
  });
});

describe('acknowledgeChainBreak', () => {
  it('records the acknowledgement, keeps the break listed, makes the chain valid, and appends its own entry to the chain', async () => {
    (rowAt(3).detail as { n: number }).n = 999;
    const after = await acknowledgeChainBreak(req, 'admin@example.test', { sequenceNumber: '3', kind: 'hash', reason: REASON });

    expect(after.valid).toBe(true);
    expect(after.openBreaks).toBe(0);
    expect(after.acknowledgedBreaks).toBe(1);
    expect(after.breaks).toHaveLength(1);
    expect(after.breaks[0].acknowledged).toMatchObject({ by: 'admin@example.test', reason: REASON });
    expect(after.message).toMatch(/1 historical break/);

    const entry = db.rows[db.rows.length - 1];
    expect(entry).toMatchObject({ action: 'audit.chain_break_acknowledged', target: 'sequence 3' });
    expect(entry.detail).toMatchObject({ sequenceNumber: '3', kind: 'hash', reason: REASON });
    // the chain including the new entry still verifies (nothing was rewritten to hide the break)
    expect((await verifyAuditChain()).checked).toBe(6);
  });

  it('stores the platform administrator as "platform", never by address', async () => {
    (rowAt(3).detail as { n: number }).n = 999;
    const after = await acknowledgeChainBreak(req, 'root@platform.test', { sequenceNumber: '3', kind: 'hash', reason: REASON });
    expect(after.breaks[0].acknowledged?.by).toBe('platform');
    expect(db.acks[0].acknowledged_by).toBe('platform');
    expect(JSON.stringify(db.rows[db.rows.length - 1])).not.toMatch(/root@platform\.test/);
  });

  it('covers only that break: a second, different break keeps the chain invalid', async () => {
    (rowAt(2).detail as { n: number }).n = 222;
    (rowAt(4).detail as { n: number }).n = 444;
    const after = await acknowledgeChainBreak(req, 'admin@example.test', { sequenceNumber: '2', kind: 'hash', reason: REASON });
    expect(after.valid).toBe(false);
    expect(after.openBreaks).toBe(1);
    expect(after.brokenAtSequence).toBe('4');
  });

  it('a row altered AGAIN after it was acknowledged is a new, open break (the acknowledgement is pinned to the row as it was)', async () => {
    (rowAt(3).detail as { n: number }).n = 999;
    await acknowledgeChainBreak(req, 'admin@example.test', { sequenceNumber: '3', kind: 'hash', reason: REASON });
    expect((await verifyAuditChain()).valid).toBe(true);

    // the stored hashes are untouched (all an attacker without the HMAC key can do); the content changes again
    rowAt(3).target = 'something-else';
    const r = await verifyAuditChain();
    expect(r.valid).toBe(false);
    expect(r.breaks[0].acknowledged).toBeUndefined();
  });

  it('refuses what is not a current break, a break already acknowledged, and a reason that says nothing', async () => {
    (rowAt(3).detail as { n: number }).n = 999;
    const status = async (input: { sequenceNumber: string; kind: string; reason: string }) => {
      try {
        await acknowledgeChainBreak(req, 'admin@example.test', input);
        return 200;
      } catch (err) {
        return err instanceof ChainAcknowledgementError ? err.status : 500;
      }
    };
    expect(await status({ sequenceNumber: '2', kind: 'hash', reason: REASON })).toBe(404); // row 2 is fine: nothing to acknowledge in advance
    expect(await status({ sequenceNumber: '3', kind: 'linkage', reason: REASON })).toBe(404); // wrong kind
    expect(await status({ sequenceNumber: '3', kind: 'hash', reason: 'fine' })).toBe(422);
    expect(await status({ sequenceNumber: 'x', kind: 'hash', reason: REASON })).toBe(422);
    expect(await status({ sequenceNumber: '3', kind: 'hash', reason: REASON })).toBe(200);
    expect(await status({ sequenceNumber: '3', kind: 'hash', reason: REASON })).toBe(409);
  });

  it('refuses to acknowledge a tail break, which means recent entries are missing', async () => {
    db.rows = db.rows.filter((r) => r.sequence_number !== '5');
    await expect(acknowledgeChainBreak(req, 'admin@example.test', { sequenceNumber: '4', kind: 'tail', reason: REASON })).rejects.toMatchObject({
      status: 422,
      code: 'ERR-CHAIN-BREAK-NOT-ACKNOWLEDGEABLE',
    });
    expect(db.acks).toHaveLength(0);
  });
});
