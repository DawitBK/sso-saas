'use client';

import { useEffect, useId, useRef } from 'react';

const FOCUSABLE = 'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * An accessible modal dialog: role=dialog + aria-modal, labelled by its title, closes on Escape and on a backdrop click,
 * keeps Tab inside, and hands focus back to whatever opened it. Replaces the browser's own `confirm()`, which cannot be styled,
 * cannot explain a consequence, and is skipped silently by some embedded browsers.
 */
export function Modal({
  open,
  title,
  onClose,
  children,
  footer,
  width = 480,
  dismissible = true,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
  /** false while an action is running, so Escape and the backdrop cannot abandon it half done. */
  dismissible?: boolean;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<Element | null>(null);

  useEffect(() => {
    if (!open) return;
    openerRef.current = document.activeElement;
    const dialog = dialogRef.current;
    const first = dialog?.querySelector<HTMLElement>('[data-autofocus]') ?? dialog?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? dialog)?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && dismissible) {
        e.stopPropagation();
        onClose();
        return;
      }
      if (e.key !== 'Tab' || !dialog) return;
      const items = Array.from(dialog.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const firstItem = items[0] as HTMLElement;
      const lastItem = items[items.length - 1] as HTMLElement;
      if (e.shiftKey && document.activeElement === firstItem) {
        e.preventDefault();
        lastItem.focus();
      } else if (!e.shiftKey && document.activeElement === lastItem) {
        e.preventDefault();
        firstItem.focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.body.style.overflow = previousOverflow;
      (openerRef.current as HTMLElement | null)?.focus?.();
    };
  }, [open, dismissible, onClose]);

  if (!open) return null;
  return (
    <div className="ui-modal-backdrop" role="presentation" onMouseDown={(e) => { if (e.target === e.currentTarget && dismissible) onClose(); }}>
      <div ref={dialogRef} className="ui-modal" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} style={{ maxWidth: width }}>
        <h2 id={titleId} className="ui-modal-title">{title}</h2>
        <div className="ui-modal-body">{children}</div>
        {footer ? <div className="ui-modal-footer">{footer}</div> : null}
      </div>
    </div>
  );
}
