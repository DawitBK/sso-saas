'use client';

import { useEffect, useState } from 'react';
import { usePathname } from 'next/navigation';
import { AdminSidebar } from '../../shared/components/AdminSidebar';
import { apiPath } from '@shared/apiPath';

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const [adminEmail, setAdminEmail] = useState('');
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const pathname = usePathname();

  useEffect(() => {
    fetch(apiPath('/api/v1/auth/session'))
      .then((res) => res.json())
      .then((json) => setAdminEmail(json?.data?.user?.email ?? ''))
      .catch(() => {});
  }, []);

  // Close the mobile drawer on navigation — same behavior as GMS's
  // PortalShell (setMobileNavOpen(false) on pathname change).
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);

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
          <span className="dot">K</span> Admin
        </div>
        <div className="who">
          <span>
            {adminEmail} ·{' '}
            {/* apiPath: a plain <a> is not basePath-aware (only next/link is). */}
            <a href={apiPath('/portal')} style={{ color: '#cbd5e1' }}>
              Back to portal
            </a>
          </span>
        </div>
      </header>
      <div className="admin-shell">
        <div className="admin-sidebar-desktop-wrap">
          <AdminSidebar />
        </div>
        <div className={`admin-mobile-overlay ${mobileNavOpen ? 'open' : ''}`} onClick={() => setMobileNavOpen(false)} />
        <div className={`admin-sidebar-mobile-wrap ${mobileNavOpen ? 'open' : ''}`} role="dialog" aria-modal="true">
          <AdminSidebar />
        </div>
        <main className="admin-main">{children}</main>
      </div>
    </>
  );
}
