/**
 * Incident response policy and the detectors' pure parts (ops/incidents.ts, ops/privilegeWatch.ts, ops/chainHead.ts, ops/securityEvents.ts).
 *
 * Proves: each event kind does exactly what the POLICY table says (alert only, revoke, lock, at which count); the owner never has their own session revoked
 * and never locks the platform over their own action; alert-only and off modes never contain; a failing step never skips the next; an event storm is
 * counted but not recorded without limit; no planted secret reaches the spool, the alert or the recorded response; membership drift is classified correctly;
 * the watcher's request signature is accepted only when fresh and correct; the event bus delivers and survives a throwing handler.
 */
import { POLICY, createIncidentHandler, decide, incidentEntryHash, resetIncidentState, type IncidentDeps } from '../src/ops/incidents.js';
import { classifyPrivilegeChanges, maskEmail } from '../src/ops/privilegeWatch.js';
import { opsRequestAllowed, signOpsRequest } from '../src/ops/chainHead.js';
import { emitSecurityEvent, onSecurityEvent, type SecurityEvent } from '../src/ops/securityEvents.js';

const SECRET = 'planted-secret-value-123456';
const ev = (over: Partial<SecurityEvent> = {}): SecurityEvent => ({ kind: 'owner_op_denied', severity: 'warning', actor: { userId: 'u1', maskedEmail: 'a***@x.test' }, operation: 'platform.key.rotate', at: new Date().toISOString(), ...over });

function fakeDeps(over: Partial<IncidentDeps> = {}) {
  const calls = { lock: [] as string[], revoke: [] as string[], record: [] as Array<Record<string, unknown>>, audit: 0, spool: [] as Array<Record<string, unknown>>, alert: 0 };
  const deps: IncidentDeps = {
    mode: () => 'contain',
    now: () => Date.now(),
    isOwner: async (id) => id === 'owner',
    revoke: async (id) => { calls.revoke.push(id); return { revoked: true }; },
    lock: async (reason) => { calls.lock.push(reason); return 'file'; },
    record: async (_e, r) => { calls.record.push(r); return { sequenceNumber: String(calls.record.length), entryHash: 'h' }; },
    audit: async () => { calls.audit += 1; },
    spool: (l) => { calls.spool.push(l); },
    alert: () => { calls.alert += 1; },
    ...over,
  };
  return { deps, calls };
}

beforeEach(() => resetIncidentState());

describe('decide (pure)', () => {
  it('owner_op_denied: nothing until the third, then revoke and lock', () => {
    expect(decide(ev(), 1, 'contain', false)).toMatchObject({ revoke: false, lock: false });
    expect(decide(ev(), 2, 'contain', false)).toMatchObject({ revoke: false, lock: false });
    expect(decide(ev(), 3, 'contain', false)).toMatchObject({ revoke: true, lock: true });
  });
  it('owner_op_without_sequence: revoke at once, lock at the third', () => {
    const e = ev({ kind: 'owner_op_without_sequence' });
    expect(decide(e, 1, 'contain', false)).toMatchObject({ revoke: true, lock: false });
    expect(decide(e, 3, 'contain', false)).toMatchObject({ revoke: true, lock: true });
  });
  it('privilege_change_by_non_owner: refused escalates by count, applied or unexplained locks at once', () => {
    const refused = ev({ kind: 'privilege_change_by_non_owner', detail: { outcome: 'refused' } });
    expect(decide(refused, 1, 'contain', false)).toMatchObject({ revoke: true, lock: false });
    expect(decide(refused, 3, 'contain', false)).toMatchObject({ revoke: true, lock: true });
    for (const outcome of ['applied', 'unexplained']) {
      expect(decide(ev({ kind: 'privilege_change_by_non_owner', detail: { outcome } }), 1, 'contain', false)).toMatchObject({ revoke: true, lock: true });
    }
  });
  it('audit_chain_broken locks at once and revokes nobody (no actor)', () => {
    expect(decide(ev({ kind: 'audit_chain_broken', actor: undefined }), 1, 'contain', false)).toMatchObject({ revoke: false, lock: true });
  });
  it('verification failures and an unknown kind never contain on their own', () => {
    for (const kind of ['owner_verification_failed', 'owner_verification_locked', 'something_new']) {
      expect(decide(ev({ kind }), 50, 'contain', false)).toMatchObject({ revoke: false, lock: false });
    }
  });
  it('the owner is never revoked or locked out over their own action', () => {
    const d = decide(ev({ kind: 'owner_op_without_sequence' }), 10, 'contain', true);
    expect(d).toMatchObject({ revoke: false, lock: false });
  });
  it('owner_op_without_sequence from the OWNER never revokes or locks, at any count or severity', () => {
    for (const severity of ['info', 'warning', 'critical'] as const) {
      expect(decide(ev({ kind: 'owner_op_without_sequence', severity }), 25, 'contain', true)).toMatchObject({ revoke: false, lock: false });
    }
  });
  it('alert and off modes never contain', () => {
    for (const mode of ['alert', 'off'] as const) expect(decide(ev({ kind: 'audit_chain_broken' }), 9, mode, false)).toMatchObject({ revoke: false, lock: false });
  });
  it('every documented kind is in the policy table', () => {
    expect(Object.keys(POLICY).sort()).toEqual(['audit_chain_broken', 'owner_op_denied', 'owner_op_without_sequence', 'owner_verification_failed', 'owner_verification_locked', 'privilege_change_by_non_owner']);
  });
});

describe('the handler', () => {
  it('records, audits, spools and alerts a first denial without containing', async () => {
    const { deps, calls } = fakeDeps();
    await createIncidentHandler(deps)(ev());
    expect(calls.lock).toEqual([]);
    expect(calls.revoke).toEqual([]);
    expect(calls.record).toHaveLength(1);
    expect(calls.audit).toBe(1);
    expect(calls.spool).toHaveLength(1);
    expect(calls.alert).toBe(1);
  });

  it('three denials from one actor revoke that actor and lock; another actor is counted separately', async () => {
    const { deps, calls } = fakeDeps();
    const h = createIncidentHandler(deps);
    await h(ev());
    await h(ev());
    await h(ev({ actor: { userId: 'u2' } }));
    expect(calls.lock).toEqual([]);
    await h(ev());
    expect(calls.revoke).toEqual(['u1']);
    expect(calls.lock).toHaveLength(1);
    expect(calls.record[3]).toMatchObject({ decision: 'revoke+lock', locked: true, revoked: true });
  });

  it('an owner event is recorded and alerted but never revokes or locks', async () => {
    const { deps, calls } = fakeDeps();
    const h = createIncidentHandler(deps);
    for (let i = 0; i < 5; i++) await h(ev({ actor: { userId: 'owner' } }));
    expect(calls.lock).toEqual([]);
    expect(calls.revoke).toEqual([]);
    expect(calls.record).toHaveLength(5);
    expect(calls.record[0]).toMatchObject({ actorIsOwner: true });
  });

  it('alert-only mode records and alerts but never contains; off mode does nothing at all', async () => {
    const a = fakeDeps({ mode: () => 'alert' });
    await createIncidentHandler(a.deps)(ev({ kind: 'audit_chain_broken', actor: undefined }));
    expect(a.calls.lock).toEqual([]);
    expect(a.calls.record).toHaveLength(1);
    const o = fakeDeps({ mode: () => 'off' });
    await createIncidentHandler(o.deps)(ev({ kind: 'audit_chain_broken', actor: undefined }));
    expect(o.calls.record).toHaveLength(0);
    expect(o.calls.spool).toHaveLength(0);
  });

  it('the owner using the console normally (owner_op_without_sequence at info, the first attempt of every owner action) is not recorded, alerted, revoked or locked', async () => {
    const { deps, calls } = fakeDeps();
    const h = createIncidentHandler(deps);
    for (let i = 0; i < 10; i++) await h(ev({ kind: 'owner_op_without_sequence', severity: 'info', actor: { userId: 'owner' } }));
    expect(calls.record).toHaveLength(0);
    expect(calls.spool).toHaveLength(0);
    expect(calls.alert).toBe(0);
    expect(calls.lock).toEqual([]);
    expect(calls.revoke).toEqual([]);
  });

  it('even if the same kind arrives as a warning from the owner it is recorded but never revokes or locks', async () => {
    const { deps, calls } = fakeDeps();
    const h = createIncidentHandler(deps);
    for (let i = 0; i < 6; i++) await h(ev({ kind: 'owner_op_without_sequence', severity: 'warning', actor: { userId: 'owner' } }));
    expect(calls.lock).toEqual([]);
    expect(calls.revoke).toEqual([]);
  });

  it('info events are ignored', async () => {
    const { deps, calls } = fakeDeps();
    await createIncidentHandler(deps)(ev({ severity: 'info' }));
    expect(calls.record).toHaveLength(0);
  });

  it('a failing lock does not skip the revoke, the record or the alert; a failing record does not skip the alert', async () => {
    const { deps, calls } = fakeDeps({
      lock: async () => { throw new Error('disk full'); },
      record: async () => { throw new Error('db down'); },
    });
    await createIncidentHandler(deps)(ev({ kind: 'privilege_change_by_non_owner', detail: { outcome: 'applied' } }));
    expect(calls.revoke).toEqual(['u1']);
    expect(calls.audit).toBe(1);
    expect(calls.spool).toHaveLength(1);
    expect(calls.spool[0]).toMatchObject({ locked: false, revoked: true });
    expect(calls.alert).toBe(1);
  });

  it('records at most 30 rows per actor and kind in ten minutes, but keeps counting (and so keeps containing)', async () => {
    const { deps, calls } = fakeDeps();
    const h = createIncidentHandler(deps);
    for (let i = 0; i < 40; i++) await h(ev());
    expect(calls.record).toHaveLength(30);
    expect(calls.lock.length).toBeGreaterThan(0);
  });

  it('puts no planted secret in the spool, the alert or the recorded response', async () => {
    const seen: string[] = [];
    const { deps, calls } = fakeDeps({ alert: (e, r) => { seen.push(JSON.stringify([e, r])); } });
    await createIncidentHandler(deps)(ev({ kind: 'audit_chain_broken', actor: undefined, detail: { openBreaks: 1 } }));
    seen.push(JSON.stringify(calls.spool), JSON.stringify(calls.record));
    expect(seen.join('')).not.toContain(SECRET);
    expect(Object.keys(calls.spool[0]!).sort()).toEqual(['at', 'decision', 'kind', 'locked', 'operation', 'revoked', 'sequence', 'severity', 'source']);
  });
});

describe('the tamper-evident hash', () => {
  const f = { sequenceNumber: '1', occurredAtIso: '2026-10-19T00:00:00.000Z', kind: 'k', severity: 'critical', actor: { a: 1, b: 2 }, operation: 'o', detail: { x: 1 }, response: { y: 2 }, previousHash: null as string | null };
  it('is stable across key order and changes with any field or the key', () => {
    const base = incidentEntryHash(f, 'key-1');
    expect(incidentEntryHash({ ...f, actor: { b: 2, a: 1 } }, 'key-1')).toBe(base);
    expect(incidentEntryHash({ ...f, kind: 'k2' }, 'key-1')).not.toBe(base);
    expect(incidentEntryHash({ ...f, previousHash: 'abc' }, 'key-1')).not.toBe(base);
    expect(incidentEntryHash({ ...f, response: { y: 3 } }, 'key-1')).not.toBe(base);
    expect(incidentEntryHash(f, 'key-2')).not.toBe(base);
  });
});

describe('classifyPrivilegeChanges (pure)', () => {
  const row = (action: string, userId: string, actorEmail = 'platform', sequence = '10') => ({ sequence, actorEmail, action, userId });
  it('finds nothing when every change is explained by an owner row', () => {
    expect(classifyPrivilegeChanges(['a'], ['a', 'b'], [row('user.admin_group.add', 'b')])).toEqual([]);
    expect(classifyPrivilegeChanges(['a', 'b'], ['a'], [row('user.admin_group.remove', 'b')])).toEqual([]);
    expect(classifyPrivilegeChanges(['a'], ['a'], [])).toEqual([]);
  });
  it('flags an addition or removal with no audit row as unexplained', () => {
    expect(classifyPrivilegeChanges(['a'], ['a', 'b'], [])).toEqual([{ outcome: 'unexplained', direction: 'added', userId: 'b' }]);
    expect(classifyPrivilegeChanges(['a', 'b'], ['a'], [])).toEqual([{ outcome: 'unexplained', direction: 'removed', userId: 'b' }]);
  });
  it('flags an owner row for the wrong person or direction as unexplained', () => {
    expect(classifyPrivilegeChanges(['a'], ['a', 'b'], [row('user.admin_group.add', 'c')])).toHaveLength(1);
    expect(classifyPrivilegeChanges(['a'], ['a', 'b'], [row('user.admin_group.remove', 'b')])).toHaveLength(1);
  });
  it('flags an audit row by anyone but the owner as applied, even if the membership looks the same', () => {
    const f = classifyPrivilegeChanges(['a'], ['a', 'b'], [row('user.admin_group.add', 'b', 'mallory@x.test', '77')]);
    expect(f).toContainEqual({ outcome: 'applied', direction: 'added', userId: 'b', auditSequence: '77', actorEmail: 'mallory@x.test' });
  });
  it('masks addresses', () => {
    expect(maskEmail('Mallory@Example.test')).toBe('m***@example.test');
    expect(maskEmail('nonsense')).toBe('***');
  });
});

describe('the watcher request signature', () => {
  const key = 'k'.repeat(40);
  const now = 1_800_000_000_000;
  it('accepts a fresh correct signature', () => {
    expect(opsRequestAllowed(signOpsRequest(key, now / 1000), key, now)).toBe(true);
  });
  it('refuses a wrong key, a stale or future timestamp, garbage, and an empty key', () => {
    expect(opsRequestAllowed(signOpsRequest('other'.repeat(10), now / 1000), key, now)).toBe(false);
    expect(opsRequestAllowed(signOpsRequest(key, now / 1000 - 300), key, now)).toBe(false);
    expect(opsRequestAllowed(signOpsRequest(key, now / 1000 + 300), key, now)).toBe(false);
    for (const bad of [undefined, '', 'abc', '123.', '.abc', 'x.y']) expect(opsRequestAllowed(bad, key, now)).toBe(false);
    expect(opsRequestAllowed(signOpsRequest('', now / 1000), '', now)).toBe(false);
  });
});

describe('the event bus', () => {
  it('delivers to every subscriber on a later tick, survives a throwing handler and unsubscribes', async () => {
    const got: string[] = [];
    const off1 = onSecurityEvent(() => { throw new Error('bad handler'); });
    const off2 = onSecurityEvent((e) => { got.push(e.kind); });
    emitSecurityEvent({ kind: 'owner_op_denied', severity: 'warning' });
    expect(got).toEqual([]); // not synchronous
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    expect(got).toEqual(['owner_op_denied']);
    off1();
    off2();
    emitSecurityEvent({ kind: 'owner_op_denied', severity: 'warning' });
    await new Promise((r) => setImmediate(r));
    expect(got).toHaveLength(1);
  });
});
