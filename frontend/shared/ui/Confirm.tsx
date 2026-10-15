'use client';

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { Modal } from './Modal';

export interface ConfirmOptions {
  title: string;
  /** What will happen, in plain words. Say who is affected and whether it can be undone. */
  message: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Styles the confirm button as destructive. */
  danger?: boolean;
  /** When set, the person must type this text before the button enables (for the irreversible ones). */
  requireText?: string;
}

type Ask = (options: ConfirmOptions) => Promise<boolean>;

const ConfirmContext = createContext<Ask | null>(null);

/** `const confirm = useConfirm(); if (!(await confirm({ title, message, danger: true }))) return;` */
export function useConfirm(): Ask {
  const ask = useContext(ConfirmContext);
  if (!ask) throw new Error('useConfirm needs <ConfirmProvider> above it');
  return ask;
}

export function ConfirmProvider({ children }: { children: React.ReactNode }) {
  const [options, setOptions] = useState<ConfirmOptions | null>(null);
  const [typed, setTyped] = useState('');
  const resolver = useRef<((v: boolean) => void) | null>(null);

  const ask = useCallback<Ask>((opts) => {
    setTyped('');
    setOptions(opts);
    return new Promise<boolean>((resolve) => { resolver.current = resolve; });
  }, []);

  const settle = useCallback((answer: boolean) => {
    resolver.current?.(answer);
    resolver.current = null;
    setOptions(null);
  }, []);

  const value = useMemo(() => ask, [ask]);
  const needsText = options?.requireText !== undefined;
  const textOk = !needsText || typed.trim() === options?.requireText;

  return (
    <ConfirmContext.Provider value={value}>
      {children}
      <Modal
        open={options !== null}
        title={options?.title ?? ''}
        onClose={() => settle(false)}
        footer={
          <>
            <button type="button" className="admin-btn secondary" onClick={() => settle(false)}>{options?.cancelLabel ?? 'Cancel'}</button>
            <button type="button" className={`admin-btn ${options?.danger ? 'danger' : ''}`} disabled={!textOk} onClick={() => settle(true)} data-autofocus={needsText ? undefined : true}>
              {options?.confirmLabel ?? 'Confirm'}
            </button>
          </>
        }
      >
        <div className="ui-modal-text">{options?.message}</div>
        {needsText ? (
          <label className="ui-field" style={{ marginTop: 14 }}>
            <span className="sub">Type <strong>{options?.requireText}</strong> to confirm</span>
            <input className="ui-input" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" data-autofocus />
          </label>
        ) : null}
      </Modal>
    </ConfirmContext.Provider>
  );
}
