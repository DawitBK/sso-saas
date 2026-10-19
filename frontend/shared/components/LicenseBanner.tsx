'use client';

import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { adminFetch } from '@shared/lib/adminApi';
import { formatDate, plural, type LicenseStatus } from '@shared/lib/license';

/**
 * SSO's own licence state, above every admin page (docs/operations/PLATFORM-LICENSING.md section 6): a banner for expiring, grace and expired.
 * Nothing at all while the licence is active or when none is configured (owner decision 2026-10-19), and
 * nothing when the status cannot be read (a licence screen must never become the reason the console looks broken).
 */
export function LicenseBanner({ isPlatformAdmin }: { isPlatformAdmin: boolean }) {
  const { data } = useQuery({
    queryKey: ['license-status'],
    queryFn: () => adminFetch<LicenseStatus>('/api/v1/licenses/status'),
    enabled: isPlatformAdmin,
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
    retry: false,
  });
  if (!isPlatformAdmin || !data) return null;

  const manage = <Link href="/admin/licenses" className="admin-link">Licences →</Link>;

  if (data.required && !data.licensed) {
    return (
      <div className="health-banner not_ready license-banner" role="alert">
        <strong>This system is not licensed.</strong>
        <span>Contact your administrator. Signing in and this licence page keep working.</span>
        {manage}
      </div>
    );
  }

  if (data.state === 'expiring') {
    const days = data.daysRemaining ?? 0;
    return (
      <div className="health-banner degraded license-banner" role="status">
        <strong>
          The SSO licence expires {days <= 0 ? 'today' : `in ${plural(days, 'day')}`} ({formatDate(data.expiresAt)}).
        </strong>
        <span>Ask your administrator to renew it so nothing becomes read-only.</span>
        {manage}
      </div>
    );
  }

  if (data.state === 'grace') {
    return (
      <div className="health-banner degraded license-banner" role="status">
        <strong>The SSO licence expired on {formatDate(data.expiresAt)}.</strong>
        <span>Everything still works until {formatDate(data.graceEndsAt)}; after that SSO becomes read-only (signing in keeps working).</span>
        {manage}
      </div>
    );
  }

  if (data.state === 'expired') {
    return (
      <div className="health-banner not_ready license-banner" role="alert">
        <strong>The SSO licence has expired.</strong>
        <span>
          {data.readOnly
            ? 'This console is read-only: changes are refused. Signing in, the portal and the licence page keep working.'
            : 'Enforcement is switched to warn-only on this server, so nothing is being refused.'}
        </span>
        {manage}
      </div>
    );
  }

  return null;
}
