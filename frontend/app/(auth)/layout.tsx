'use client';

import { useThemeStore, type Theme } from '../../state/theme.store';

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  const { theme, setTheme } = useThemeStore();

  return (
    <div className="sso-shell">
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
      <div className="sso-card">{children}</div>
    </div>
  );
}
