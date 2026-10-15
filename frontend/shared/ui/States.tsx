'use client';

import { AlertTriangle, Inbox, RefreshCw } from 'lucide-react';
import { ApiError } from '../lib/adminApi';

/** A grey shimmer block that stands in for content that has not arrived yet (keeps the layout from jumping). */
export function Skeleton({ width = '100%', height = 14, style }: { width?: number | string; height?: number | string; style?: React.CSSProperties }) {
  return <span className="ui-skeleton" aria-hidden="true" style={{ width, height, ...style }} />;
}

/** The loading state of a whole admin page: a heading and a few cards. Announced once to assistive technology. */
export function PageSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="admin-visually-hidden">Loading…</span>
      <div style={{ display: 'grid', gap: 8, marginBottom: 22 }}>
        <Skeleton width={220} height={24} />
        <Skeleton width={360} height={13} />
      </div>
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="admin-card" style={{ display: 'grid', gap: 10 }}>
          <Skeleton width={160} height={15} />
          <Skeleton height={13} />
          <Skeleton width="70%" height={13} />
        </div>
      ))}
    </div>
  );
}

/** Something failed to load: says what the server said, offers a retry, and quotes the reference to give an administrator. */
export function ErrorState({ error, onRetry, title = 'This could not be loaded' }: { error: unknown; onRetry?: () => void; title?: string }) {
  const message = error instanceof Error ? error.message : 'Something went wrong.';
  const ref = error instanceof ApiError && error.requestId ? error.requestId : '';
  return (
    <div className="admin-card ui-state error" role="alert">
      <AlertTriangle size={28} aria-hidden="true" color="var(--danger)" />
      <h2>{title}</h2>
      <p>{message}</p>
      {ref ? <span className="ui-ref">Reference {ref}</span> : null}
      {onRetry ? (
        <button type="button" className="admin-btn secondary" onClick={onRetry}>
          <RefreshCw size={14} aria-hidden="true" /> Try again
        </button>
      ) : null}
    </div>
  );
}

/** A list or table with nothing in it: says why, and what to do next. */
export function EmptyState({ title, children, action }: { title: string; children?: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="ui-empty">
      <Inbox aria-hidden="true" />
      <div className="ui-empty-title">{title}</div>
      {children ? <div className="ui-empty-desc">{children}</div> : null}
      {action}
    </div>
  );
}
