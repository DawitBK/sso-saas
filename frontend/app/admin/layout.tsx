'use client';

import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { AdminSidebar } from '../../shared/components/AdminSidebar';
import { apiPath } from '@shared/apiPath';
import { useBranding } from '@shared/branding/BrandingProvider';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const [adminEmail, setAdminEmail] = useState('');
  const [isPlatformAdmin, setIsPlatformAdmin] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pathname = usePathname();
  const { productName } = useBranding();

  useEffect(() => {
    fetch(apiPath('/api/v1/auth/session'))
      .then((res) => res.json())
      .then((json) => {
        setAdminEmail(json?.data?.user?.email ?? '');
        setIsPlatformAdmin(Boolean(json?.data?.user?.isPlatformAdmin));
      })
      .catch(() => {});
  }, []);

  // Close the mobile drawer on navigation — same behavior as GMS's
  // PortalShell. This is React's documented "adjusting state when a prop
  // changes" pattern (react.dev/reference/react/useState), not an effect: the
  // drawer closes during the render that first sees the new pathname, so it is
  // never painted open on the page you just navigated to. The effect this
  // replaces rendered the new route with the drawer still open for one frame,
  // and react-hooks/set-state-in-effect rejects it outright under
  // eslint-config-next 16.
  const [lastPathname, setLastPathname] = useState(pathname);
  if (lastPathname !== pathname) {
    setLastPathname(pathname);
    setMobileNavOpen(false);
  }

  return (
    <>
      <header className="admin-header">
        <button
          type="button"
          className="admin-header-menu-btn"
          aria-label="Open menu"
          aria-expanded={mobileNavOpen}
          onClick={() => setMobileNavOpen(true)}
        >
          <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="4" y1="6" x2="20" y2="6" />
            <line x1="4" y1="12" x2="20" y2="12" />
            <line x1="4" y1="18" x2="20" y2="18" />
          </svg>
        </button>
        <div className="brand">
          <span className="dot" aria-hidden="true">{(productName.trim()[0] ?? 'K').toUpperCase()}</span> Admin
        </div>
        <div className="who">
          <span>
            {adminEmail} ·{' '}
            {/* apiPath: a plain <a> is not basePath-aware (only next/link is).
                suppressHydrationWarning: AdGuard (and similar extensions) injects
                an inline style attribute on this link before React hydrates,
                which otherwise trips a false-positive hydration mismatch. */}
            <a href={apiPath('/portal')} suppressHydrationWarning>Back to portal</a>
          </span>
        </div>
      </header>
      <div className="admin-shell">
        <div className="admin-sidebar-desktop-wrap">
          <AdminSidebar isPlatformAdmin={isPlatformAdmin} />
        </div>
        <div
          className={`admin-mobile-overlay ${mobileNavOpen ? 'open' : ''}`}
          onClick={() => setMobileNavOpen(false)}
          role="button"
          tabIndex={0}
          aria-label="Close menu"
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ' || e.key === 'Escape') {
              e.preventDefault();
              setMobileNavOpen(false);
            }
          }}
        />
        <div className={`admin-sidebar-mobile-wrap ${mobileNavOpen ? 'open' : ''}`} role="dialog" aria-modal="true">
          <AdminSidebar isPlatformAdmin={isPlatformAdmin} />
        </div>
        <main className="admin-main">{children}</main>
      </div>
    </>
  );
}
