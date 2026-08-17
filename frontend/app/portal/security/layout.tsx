'use client';

import { useThemeStore, type Theme } from '../../../state/theme.store';

export default function SecurityLayout({ children }: { children: React.ReactNode }) {
  const { theme, setTheme } = useThemeStore();

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'linear-gradient(135deg, var(--grad-1) 0%, var(--grad-2) 100%)',
        padding: '24px',
      }}
    >
      <div className="sso-theme-selector">
        {(['light', 'dark-black', 'dark-blue'] as Theme[]).map((t) => (
          <button
            key={t}
            type="button"
            className={`theme-dot ${t} ${theme === t ? 'active' : ''}`}
            onClick={() => setTheme(t)}
            aria-label={`${t} theme`}
            title={t}
          />
        ))}
      </div>
      <div className="sso-card" style={{ maxWidth: '480px' }}>
        {children}
      </div>
    </div>
  );
}
