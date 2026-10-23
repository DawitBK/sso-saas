'use client';

import { useRef, useState, useSyncExternalStore } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  Users,
  UsersRound,
  ShieldCheck,
  AppWindow,
  Activity,
  LogIn,
  KeyRound,
  ScrollText,
  SlidersHorizontal,
  HeartPulse,
  BadgeCheck,
  Fingerprint,
  ShieldAlert,
  ChevronRight,
  LogOut,
  type LucideIcon,
} from 'lucide-react';
import { useThemeStore, type Theme } from '../../state/theme.store';
import { apiPath } from '@shared/apiPath';

interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Shown to the platform administrator only. */
  platformAdminOnly?: boolean;
}
interface NavSection {
  href?: string;
  label?: string;
  icon?: LucideIcon;
  group?: string;
  items?: NavItem[];
}

// Mirrors admin/head.ejs's __navSections.
const NAV_SECTIONS: NavSection[] = [
  { href: '/admin', label: 'Dashboard', icon: LayoutDashboard },
  {
    group: 'Identity',
    items: [
      { href: '/admin/users', label: 'Users', icon: Users },
      { href: '/admin/groups', label: 'Groups', icon: UsersRound },
      { href: '/admin/dms-roles', label: 'DMS Roles', icon: ShieldCheck },
    ],
  },
  { href: '/admin/clients', label: 'Applications', icon: AppWindow },
  {
    group: 'Security',
    items: [
      { href: '/admin/sessions', label: 'Sessions', icon: Activity },
      { href: '/admin/logins', label: 'Sign-ins', icon: LogIn },
      { href: '/admin/keys', label: 'Keys', icon: KeyRound, platformAdminOnly: true },
      { href: '/admin/audit', label: 'Audit', icon: ScrollText },
      { href: '/admin/owner-verification', label: 'Owner verification', icon: Fingerprint, platformAdminOnly: true },
      { href: '/admin/security-incidents', label: 'Security incidents', icon: ShieldAlert, platformAdminOnly: true },
    ],
  },
  {
    group: 'System',
    items: [
      { href: '/admin/system', label: 'System health', icon: HeartPulse },
      { href: '/admin/settings', label: 'Settings', icon: SlidersHorizontal },
      { href: '/admin/licenses', label: 'Licences', icon: BadgeCheck, platformAdminOnly: true },
    ],
  },
];

const MIN_W = 180;
const MAX_W = 500;
const DEFAULT_W = 302;
// Same key the EJS admin console used, so a width picked there carries over.
const WIDTH_KEY = 'kg-sidebar-w';

const clampWidth = (w: number) => Math.max(MIN_W, Math.min(MAX_W, w));

// The persisted width is browser state with no value during SSR, so it is read
// through useSyncExternalStore: the server snapshot renders DEFAULT_W,
// hydration matches it, and the stored width applies on the first client
// render. `storage` covers another tab changing it; local writes notify
// through `widthListeners` because `storage` does not fire in the tab that
// wrote it.
const widthListeners = new Set<() => void>();

function subscribeWidth(onChange: () => void) {
  widthListeners.add(onChange);
  window.addEventListener('storage', onChange);
  return () => {
    widthListeners.delete(onChange);
    window.removeEventListener('storage', onChange);
  };
}

function getWidthSnapshot() {
  const saved = Number(localStorage.getItem(WIDTH_KEY));
  return Number.isFinite(saved) && saved > 0 ? clampWidth(saved) : DEFAULT_W;
}

const getServerWidthSnapshot = () => DEFAULT_W;

function storeWidth(w: number) {
  localStorage.setItem(WIDTH_KEY, String(w));
  widthListeners.forEach((cb) => cb());
}

export function AdminSidebar({ isPlatformAdmin = false }: { isPlatformAdmin?: boolean }) {
  const pathname = usePathname();
  const { theme, setTheme } = useThemeStore();
  const sidebarRef = useRef<HTMLElement>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    new Set(['Identity', 'Security', 'System']),
  );

  // Persisted drag-resize. The width is real React state now, not a direct
  // `el.style.width` mutation with a mount effect to restore it. That mattered
  // for more than lint: `aria-valuenow` below read `sidebarRef.current` during
  // render, so it was `null` on the first pass and never re-read afterwards —
  // a screen reader was told the splitter was at 302 no matter where the user
  // had actually dragged or arrow-keyed it. react-hooks/refs catches exactly
  // this, and is an error under eslint-config-next 16.
  const width = useSyncExternalStore(subscribeWidth, getWidthSnapshot, getServerWidthSnapshot);

  const isActive = (href: string) =>
    href === '/admin' ? pathname === '/admin' : pathname === href || pathname?.startsWith(href + '/');

  // Keyboard equivalent of the mouse-drag resize below (WAI-ARIA's
  // "window splitter" pattern: role="separator" + arrow-key resize) — the
  // handle previously had no keyboard path at all, mouse-drag only.
  const onResizeKeyDown = (e: React.KeyboardEvent) => {
    const STEP = 20;
    let delta = 0;
    if (e.key === 'ArrowLeft') delta = -STEP;
    else if (e.key === 'ArrowRight') delta = STEP;
    else return;
    e.preventDefault();
    storeWidth(clampWidth(width + delta));
  };

  const onResizeStart = (e: React.MouseEvent) => {
    e.preventDefault();
    const el = sidebarRef.current;
    if (!el) return;
    const startX = e.clientX;
    const startW = el.offsetWidth;
    // The drag itself still writes `el.style.width` directly, once per
    // mousemove, rather than re-rendering the whole sidebar on every frame.
    // The committed width is published to the store on mouseup, which is what
    // React and `aria-valuenow` then agree on.
    const onMove = (me: MouseEvent) => {
      el.style.width = `${clampWidth(startW + (me.clientX - startX))}px`;
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      storeWidth(clampWidth(el.offsetWidth));
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
    <aside ref={sidebarRef} className="admin-sidebar" style={{ width }}>
      <div
        className="admin-sidebar-resize-handle"
        onMouseDown={onResizeStart}
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize sidebar"
        aria-valuenow={width}
        aria-valuemin={MIN_W}
        aria-valuemax={MAX_W}
        tabIndex={0}
        onKeyDown={onResizeKeyDown}
      />
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
                <ChevronRight className="chevron" aria-hidden="true" />
              </summary>
              <div className="group-items">
                {section.items!.filter((item) => !item.platformAdminOnly || isPlatformAdmin).map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={isActive(item.href) ? 'active' : ''}
                    aria-current={isActive(item.href) ? 'page' : undefined}
                  >
                    <item.icon className="nav-icon" aria-hidden="true" />
                    {item.label}
                  </Link>
                ))}
              </div>
            </details>
          ) : (
            <Link
              key={section.href}
              href={section.href!}
              className={isActive(section.href!) ? 'active' : ''}
              aria-current={isActive(section.href!) ? 'page' : undefined}
            >
              {section.icon && <section.icon className="nav-icon" aria-hidden="true" />}
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
          <LogOut className="nav-icon" aria-hidden="true" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
