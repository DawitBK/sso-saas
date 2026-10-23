'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { OwnerVerificationDialog } from './OwnerVerificationDialog';
import { registerOwnerAuthoriser, type AuthoriseResult } from './ownerClient';
import type { Refusal, Ticket } from './ownerLogic';

interface Pending {
  id: number;
  refusal: Refusal;
  resolve: (result: AuthoriseResult) => void;
}

/**
 * Mounted once in the admin layout. Registers the function `ownerFetch` calls when the server says an action needs the owner's
 * authorisation, and shows the verification dialog for it. Requests that arrive while a dialog is open wait their turn.
 */
export function OwnerVerificationProvider({ children }: { children: React.ReactNode }) {
  const [pending, setPending] = useState<Pending | null>(null);
  const pendingRef = useRef<Pending | null>(null);
  const queue = useRef<Promise<unknown>>(Promise.resolve());
  const counter = useRef(0);

  useEffect(() => {
    pendingRef.current = pending;
  });

  useEffect(() => {
    return registerOwnerAuthoriser((refusal) => {
      const show = () =>
        new Promise<AuthoriseResult>((resolve) => {
          counter.current += 1;
          setPending({ id: counter.current, refusal, resolve });
        });
      const result = queue.current.then(show, show);
      queue.current = result.catch(() => undefined);
      return result;
    });
  }, []);

  const settle = useCallback((result: AuthoriseResult) => {
    pendingRef.current?.resolve(result);
    setPending(null);
  }, []);

  const onTicket = useCallback((ticket: Ticket) => settle({ kind: 'ticket', ticket }), [settle]);
  const onCancel = useCallback((notEnrolled: boolean) => settle({ kind: notEnrolled ? 'not-enrolled' : 'cancelled' }), [settle]);

  return (
    <>
      {children}
      {pending ? (
        <OwnerVerificationDialog
          key={pending.id}
          operation={pending.refusal.operation}
          target={pending.refusal.target}
          label={pending.refusal.label}
          warning={pending.refusal.warning}
          notice={pending.refusal.code === 'OWNER_AUTHORISATION_INVALID' ? 'The earlier authorisation was not accepted. It may have run out or already been used. Please authorise again.' : undefined}
          notEnrolled={pending.refusal.code === 'OWNER_NOT_ENROLLED'}
          onTicket={onTicket}
          onCancel={onCancel}
        />
      ) : null}
    </>
  );
}
