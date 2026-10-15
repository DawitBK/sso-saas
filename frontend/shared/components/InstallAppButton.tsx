'use client';

import { useState } from 'react';
import { usePwaInstall } from '../hooks/usePwaInstall';

export function InstallAppButton() {
  const { canInstall, isIos, isInstalled, promptInstall } = usePwaInstall();
  const [showIosHint, setShowIosHint] = useState(false);

  if (isInstalled || (!canInstall && !isIos)) return null;

  return (
    <div style={{ position: 'relative' }}>
      <button
        type="button"
        onClick={() => (canInstall ? void promptInstall() : setShowIosHint((v) => !v))}
        style={{
          fontSize: '13px',
          fontWeight: 600,
          color: 'var(--brand)',
          textDecoration: 'none',
          padding: '8px 16px',
          borderRadius: '8px',
          border: '1px solid var(--border)',
          background: 'var(--card)',
          cursor: 'pointer',
          transition: 'all .12s ease',
          whiteSpace: 'nowrap',
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: '38px',
        }}
      >
        Install App
      </button>
      {showIosHint && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            zIndex: 10,
            marginTop: '8px',
            width: '224px',
            borderRadius: '8px',
            padding: '12px',
            fontSize: '11px',
            color: 'var(--muted)',
            background: 'var(--card)',
            border: '1px solid var(--border)',
            boxShadow: '0 8px 24px var(--shadow)',
          }}
        >
          Tap the Share icon, then &quot;Add to Home Screen&quot;.
        </div>
      )}
    </div>
  );
}
