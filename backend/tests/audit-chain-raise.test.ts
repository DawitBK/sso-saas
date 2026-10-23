/**
 * When the audit-chain check raises `audit_chain_broken` (ops/auditChain.ts rememberAuditChainResult).
 *
 * Found on the mirror 2026-10-21: acknowledging the FIRST of two known breaks recorded a second incident, because the "already raised" key was
 * `<open count>:<first open break>` and both change when a break is explained. Proves: the same open set is raised once; explaining some of the breaks
 * (the open set shrinks) raises nothing; a break that was not open before, or a larger open count, raises again; a clean chain resets it.
 */
import type { ChainBreak, ChainVerification } from '../src/admin/audit.js';
import { rememberAuditChainResult, resetAuditChainState } from '../src/ops/auditChain.js';
import { onSecurityEvent, type SecurityEvent } from '../src/ops/securityEvents.js';

const brk = (seq: string, acknowledged = false): ChainBreak => ({
  sequenceNumber: seq,
  kind: 'hash',
  message: `Entry ${seq} was modified`,
  acknowledgeable: true,
  ...(acknowledged ? { acknowledged: { by: 'platform', at: '2026-10-21T00:00:00.000Z', reason: 'a known, explained break from July' } } : {}),
});

function result(breaks: ChainBreak[], extraOpen = 0): ChainVerification {
  const open = breaks.filter((b) => !b.acknowledged);
  return {
    valid: open.length + extraOpen === 0,
    checked: 10,
    legacyCount: 0,
    breaks,
    openBreaks: open.length + extraOpen,
    acknowledgedBreaks: breaks.length - open.length,
    truncated: false,
    brokenAtSequence: open[0]?.sequenceNumber,
    message: 'x',
  };
}

const events: SecurityEvent[] = [];
let off: () => void;
const settle = () => new Promise((r) => setImmediate(() => setImmediate(r)));

beforeEach(() => {
  resetAuditChainState();
  events.length = 0;
  off = onSecurityEvent((e) => { if (e.kind === 'audit_chain_broken') events.push(e); });
});
afterEach(() => off());

describe('audit_chain_broken is raised for a NEW problem only', () => {
  it('raises once for a break and not again while the same break stays open', async () => {
    rememberAuditChainResult(result([brk('2'), brk('5')]));
    rememberAuditChainResult(result([brk('2'), brk('5')]));
    await settle();
    expect(events).toHaveLength(1);
    expect(events[0]!.detail).toMatchObject({ openBreaks: 2, firstOpenBreak: '2' });
  });

  it('does NOT raise when one of two known breaks is acknowledged (the mirror incident #3)', async () => {
    rememberAuditChainResult(result([brk('2'), brk('5')]));
    await settle();
    expect(events).toHaveLength(1);
    rememberAuditChainResult(result([brk('2', true), brk('5')])); // the first acknowledged: one open, a different first open break
    await settle();
    expect(events).toHaveLength(1);
    rememberAuditChainResult(result([brk('2', true), brk('5', true)])); // all explained: valid
    await settle();
    expect(events).toHaveLength(1);
  });

  it('raises again for a break that was not open before, and for a larger open count', async () => {
    rememberAuditChainResult(result([brk('2'), brk('5')]));
    rememberAuditChainResult(result([brk('2', true), brk('5')]));
    rememberAuditChainResult(result([brk('2', true), brk('5'), brk('9')])); // a new row broke
    await settle();
    expect(events).toHaveLength(2);
    expect(events[1]!.detail).toMatchObject({ openBreaks: 2 });
    rememberAuditChainResult(result([brk('2', true), brk('5'), brk('9')], 3)); // breaks beyond the reporting limit: the count grew
    await settle();
    expect(events).toHaveLength(3);
  });

  it('raises again when an acknowledged row is edited afterwards (it is open again)', async () => {
    rememberAuditChainResult(result([brk('2'), brk('5')]));
    rememberAuditChainResult(result([brk('2', true), brk('5')]));
    rememberAuditChainResult(result([brk('2'), brk('5')])); // the acknowledgement no longer covers sequence 2
    await settle();
    expect(events).toHaveLength(2);
  });

  it('a clean chain resets it, so a later break is raised again', async () => {
    rememberAuditChainResult(result([brk('2')]));
    rememberAuditChainResult(result([brk('2', true)]));
    rememberAuditChainResult(result([brk('2', true), brk('7')]));
    await settle();
    expect(events).toHaveLength(2);
  });
});
