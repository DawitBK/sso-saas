/**
 * The audit chain's health between visits to the Audit page.
 *
 * Verifying walks every row, so it is not done on each health probe. A background job (every six hours, and shortly after start) runs it and
 * keeps the outcome here; the Audit page's "Verify integrity" button refreshes it. Readiness then reports `auditChain`: degraded while any
 * break is unexplained (an acknowledged one does not count), so a monitor and the System page raise the alarm without anybody opening the
 * Audit page. Degraded, never not-ready: a tampered log is something to investigate, not a reason to stop signing people in.
 */
import { verifyAuditChain, type ChainVerification } from '../admin/audit.js';
import { logger } from '../logging/logger.js';
import type { Check } from './readiness.js';
import { emitSecurityEvent } from './securityEvents.js';

export interface AuditChainState {
  checkedAt: string;
  valid: boolean;
  checked: number;
  openBreaks: number;
  acknowledgedBreaks: number;
  firstOpenBreak: string | null;
}

let last: AuditChainState | null = null;
/**
 * What was last reported as a security event: the open (unacknowledged) breaks at that time, as `sequence:kind` keys, and how many there were in all. A break
 * already reported is not raised again, and neither is a SHRINKING set: acknowledging one of two known breaks leaves the other open, which is the same
 * incident getting smaller, not a new one (found on the mirror 2026-10-21: the first acknowledgement recorded a second `audit_chain_broken` incident because
 * the old key was `<open count>:<first open break>`, which changes whenever a break is explained). Only a break that was not open before, or a larger open
 * count, is a new event.
 */
let lastRaised: { keys: Set<string>; open: number } | null = null;

/** Remember an outcome (from a scheduled run, the Audit page, or an acknowledgement), and raise the alarm in the log when it is bad. */
export function rememberAuditChainResult(result: ChainVerification): void {
  const wasValid = last?.valid ?? true;
  last = {
    checkedAt: new Date().toISOString(),
    valid: result.valid,
    checked: result.checked,
    openBreaks: result.openBreaks,
    acknowledgedBreaks: result.acknowledgedBreaks,
    firstOpenBreak: result.brokenAtSequence ?? null,
  };
  // A new unexplained break is a security event (ops/incidents.ts decides what to do); the same one is not raised again every six hours, and explaining
  // one of several (the open set only shrinks) is not a new one either.
  if (result.valid) lastRaised = null;
  else {
    const keys = new Set(result.breaks.filter((b) => !b.acknowledged).map((b) => `${b.sequenceNumber}:${b.kind}`));
    const previous = lastRaised;
    const isNew = previous === null || result.openBreaks > previous.open || [...keys].some((k) => !previous.keys.has(k));
    lastRaised = { keys, open: result.openBreaks };
    if (isNew) {
      emitSecurityEvent({ kind: 'audit_chain_broken', severity: 'critical', operation: 'audit_chain_verify', detail: { openBreaks: result.openBreaks, firstOpenBreak: result.brokenAtSequence ?? null, wasValid } });
    }
  }
  // Logged at error level whenever it is bad (every scheduled run while it stays bad), so a log watcher sees it too.
  if (!result.valid) {
    logger.error({ openBreaks: result.openBreaks, firstOpenBreak: result.brokenAtSequence, wasValid }, '[idp:audit] ALERT: the admin audit chain does not verify');
  }
}

/** Verify now and remember the outcome. Rethrows a failure to read the table; the caller decides what to say. */
export async function runAuditChainCheck(): Promise<ChainVerification> {
  const result = await verifyAuditChain();
  rememberAuditChainResult(result);
  return result;
}

export function lastAuditChainState(): AuditChainState | null {
  return last;
}

/** Readiness check. Not yet verified since start is fine: the job runs a minute after boot. */
export function auditChainCheck(): Check {
  if (!last) return { state: 'ok', detail: 'Not verified since the process started yet.' };
  if (last.valid) return { state: 'ok' };
  return {
    state: 'degraded',
    detail: `The admin audit chain has ${last.openBreaks} unexplained break(s), the first at sequence ${last.firstOpenBreak}. Open Admin > Audit log and verify integrity.`,
  };
}

/** Test hook. */
export function resetAuditChainState(): void {
  last = null;
  lastRaised = null;
}
