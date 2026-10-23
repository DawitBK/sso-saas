/**
 * A tiny in-process bus for security events.
 *
 * Code that notices something wrong (an owner-only operation attempted without verification, a privilege change by someone who is not the owner, a broken
 * audit chain) calls `emitSecurityEvent`; the incident handler subscribes once at boot with `onSecurityEvent`. The two sides never import each other, so the
 * detectors can be written and tested without the response, and the response without the detectors.
 *
 * Rules for every caller: put NO secret in `detail` (no codes, answers, tokens, passwords, keys, full mailbox addresses), and never wait on the outcome:
 * emitting must not change what the caller does or how long it takes. A handler that throws is logged and ignored.
 */
import { EventEmitter } from 'node:events';
import { logger } from '../logging/logger.js';

export type SecuritySeverity = 'info' | 'warning' | 'critical';

/** Kinds in use; a new kind is just a new string (document it where it is raised). */
export type SecurityEventKind =
  | 'owner_op_denied' // an owner-only operation was refused (no valid owner authorisation)
  | 'owner_op_without_sequence' // an owner-only operation was attempted outside the verification sequence
  | 'owner_verification_failed' // a wrong answer or code in the owner sequence
  | 'owner_verification_locked' // the sequence locked after repeated failures
  | 'privilege_change_by_non_owner' // administrator rights changed by anyone but the owner
  | 'audit_chain_broken' // the admin audit hash chain failed verification
  | (string & {});

export interface SecurityEvent {
  kind: SecurityEventKind;
  severity: SecuritySeverity;
  /** Who did it, when known. Ids and a masked address only. */
  actor?: { userId?: string; maskedEmail?: string; sessionId?: string; ip?: string };
  /** The owner-only operation key, when there is one. */
  operation?: string;
  /** Short, secret-free facts. */
  detail?: Record<string, string | number | boolean | null>;
  at: string;
}

const bus = new EventEmitter();
bus.setMaxListeners(20);

export function emitSecurityEvent(event: Omit<SecurityEvent, 'at'> & { at?: string }): void {
  const full: SecurityEvent = { ...event, at: event.at ?? new Date().toISOString() };
  // Deliver on the next tick so a slow or failing handler can never delay or break the request that raised the event.
  setImmediate(() => {
    for (const handler of bus.listeners('event') as Array<(e: SecurityEvent) => unknown>) {
      try {
        const out = handler(full);
        if (out && typeof (out as Promise<unknown>).catch === 'function') {
          (out as Promise<unknown>).catch((err) => logger.error({ err, kind: full.kind }, 'security event handler failed'));
        }
      } catch (err) {
        logger.error({ err, kind: full.kind }, 'security event handler failed');
      }
    }
  });
}

/** Subscribe; returns an unsubscribe function. */
export function onSecurityEvent(handler: (event: SecurityEvent) => unknown): () => void {
  bus.on('event', handler);
  return () => bus.off('event', handler);
}
