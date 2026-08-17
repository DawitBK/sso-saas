'use client';

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useThemeStore, type Theme } from '../../state/theme.store';
import { apiPath } from '@shared/apiPath';

interface NavItem {
  href: string;
  label: string;
}
interface NavSection {
  href?: string;
  label?: string;
  group?: string;
  items?: NavItem[];
}

// Mirrors admin/head.ejs's __navSections.
const NAV_SECTIONS: NavSection[] = [
  { href: '/admin', label: 'Dashboard' },
  {
    group: 'Identity',
    items: [
      { href: '/admin/users', label: 'Users' },
      { href: '/admin/groups', label: 'Groups' },
      { href: '/admin/dms-roles', label: 'DMS Roles' },
    ],
  },
  { href: '/admin/clients', label: 'Clients' },
  {
    group: 'Security',
    items: [
      { href: '/admin/sessions', label: 'Sessions' },
      { href: '/admin/logins', label: 'Sign-ins' },
      { href: '/admin/keys', label: 'Keys' },
      { href: '/admin/audit', label: 'Audit' },
    ],
  },
];

const MIN_W = 180;
const MAX_W = 500;
const DEFAULT_W = 302;

export function AdminSidebar() {
  const pathname = usePathname();
  const { theme, setTheme } = useThemeStore();
  const sidebarRef = useRef<HTMLElement>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    new Set(['Identity', 'Security']),
  );

  const isActive = (href: string) =>
    href === '/admin' ? pathname === '/admin' : pathname === href || pathname?.startsWith(href + '/');

  // Persisted drag-resize (mirrors admin/foot.ejs's sidebar-resize script —
  // same localStorage key so a width picked on the EJS console carries over).
  useEffect(() => {
    const el = sidebarRef.current;
    if (!el) return;
    const saved = localStorage.getItem('kg-sidebar-w');
    if (saved) el.style.width = `${saved}px`;
  }, []);

  const onResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    const el = sidebarRef.current;
    if (!el) return;
    const startX = e.clientX;
    const startW = el.offsetWidth;
    const onMove = (me: MouseEvent) => {
      const w = Math.max(MIN_W, Math.min(MAX_W, startW + (me.clientX - startX)));
      el.style.width = `${w}px`;
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      localStorage.setItem('kg-sidebar-w', String(el.offsetWidth));
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  };

  // Real sign-out: fetch a fresh CSRF token, then proxy to the actual
  // /portal/logout (full session revocation) — not a form posting to
  // /api/auth/logout, which never existed on this backend.
  const handleSignOut = async () => {
    try {
      const sessionRes = await fetch(apiPath('/api/v1/auth/session'));
      const sessionJson = await sessionRes.json();
      const csrf = sessionJson?.data?.csrf ?? '';
      // Direct fetch to the real backend path — see the matching comment in
      // app/portal/page.tsx for why this can't go through a separate
      // /api/proxy/* route (the CSRF cookie is scoped to Path=/portal).
      const res = await fetch(apiPath('/portal/logout'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf }).toString(),
      });
      window.location.href = res.url || apiPath('/portal');
    } catch {
      // apiPath: window.location is not basePath-aware — see apiPath.ts.
      window.location.href = apiPath('/portal');
    }
  };

  const toggleGroup = (group: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(group)) next.delete(group);
      else next.add(group);
      return next;
    });
  };

  return (
    <aside ref={sidebarRef} className="admin-sidebar" style={{ width: DEFAULT_W }}>
      <div className="admin-sidebar-resize-handle" onMouseDown={onResizeStart} />
      <nav>
        {NAV_SECTIONS.map((section) =>
          section.group ? (
            <details key={section.group} className="nav-group" open={expandedGroups.has(section.group)}>
              <summary
                onClick={(e) => {
                  e.preventDefault();
                  toggleGroup(section.group!);
                }}
              >
                {section.group}
              </summary>
              <div className="group-items">
                {section.items!.map((item) => (
                  <Link key={item.href} href={item.href} className={isActive(item.href) ? 'active' : ''}>
                    {item.label}
                  </Link>
                ))}
              </div>
            </details>
          ) : (
            <Link key={section.href} href={section.href!} className={isActive(section.href!) ? 'active' : ''}>
              {section.label}
            </Link>
          ),
        )}
      </nav>
      <div className="admin-sidebar-bottom">
        <div className="theme-selector">
          <span className="theme-label">Theme</span>
          <button type="button" className={`theme-dot light ${theme === 'light' ? 'active' : ''}`} onClick={() => setTheme('light' as Theme)} aria-label="Light theme" title="Light" />
          <button type="button" className={`theme-dot dark-black ${theme === 'dark-black' ? 'active' : ''}`} onClick={() => setTheme('dark-black' as Theme)} aria-label="Black theme" title="Black" />
          <button type="button" className={`theme-dot dark-blue ${theme === 'dark-blue' ? 'active' : ''}`} onClick={() => setTheme('dark-blue' as Theme)} aria-label="Blue theme" title="Blue" />
        </div>
        <button type="button" className="admin-sidebar-signout" onClick={handleSignOut}>
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          Sign out
        </button>
      </div>
    </aside>
  );
}
