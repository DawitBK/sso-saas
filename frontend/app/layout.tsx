import { cache } from 'react';
import { headers } from 'next/headers';
import type { Metadata, Viewport } from 'next';
import { Inter } from 'next/font/google';
import { Providers } from '../providers/Providers';
import { apiPath } from '@shared/apiPath';
import { brandingCss, fetchBranding } from '../shared/branding/branding';
import { BrandingProvider } from '../shared/branding/BrandingProvider';
import './globals.css';

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

// The branding is read from the backend on every page view (settings are editable in the console), so no page is prerendered.
export const dynamic = 'force-dynamic';

// One backend call per request even though both metadata and the layout need it.
const branding = cache(fetchBranding);

export async function generateMetadata(): Promise<Metadata> {
  const b = await branding();
  return {
    title: { default: b.productName, template: `%s · ${b.productName}` },
    description: `${b.productName} — ${b.tagline}`,
    manifest: apiPath('/manifest.json'),
    icons: {
      icon: [
        { url: apiPath('/icons/icon-192.png'), sizes: '192x192', type: 'image/png' },
        { url: apiPath('/icons/icon-512.png'), sizes: '512x512', type: 'image/png' },
      ],
      apple: apiPath('/icons/apple-touch-icon.png'),
      shortcut: apiPath('/icons/favicon.png'),
    },
  };
}

export async function generateViewport(): Promise<Viewport> {
  const b = await branding();
  return { themeColor: b.accentColor };
}

// Set the theme before first paint so there's no light/dark flash (mirrors
// the inline script in SSO/frontend/src/views/head.ejs — zustand's own
// rehydration happens after hydration, which is too late to avoid the flash).
const NO_FLASH_SCRIPT = `
(function () {
  try {
    var raw = localStorage.getItem('kg-theme');
    var saved = raw ? JSON.parse(raw)?.state?.theme : null;
    var themes = ['light', 'dark-black', 'dark-blue'];
    if (saved && themes.indexOf(saved) !== -1) {
      document.documentElement.setAttribute('data-theme', saved);
    } else {
      var sys = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark-black' : 'light';
      document.documentElement.setAttribute('data-theme', sys);
    }
  } catch (e) {}
})();
`;

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const b = await branding();
  // The per-request nonce proxy.ts put on the Content-Security-Policy: the one inline script (the theme, which must run before first
  // paint) is allowed to execute by carrying it. Absent when the policy is switched off.
  const nonce = (await headers()).get('x-nonce') ?? undefined;
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: NO_FLASH_SCRIPT }} />
        {/* brandingCss only ever receives colours that passed sanitizeBranding (#rrggbb). */}
        <style id="branding" nonce={nonce} dangerouslySetInnerHTML={{ __html: brandingCss(b) }} />
      </head>
      <body suppressHydrationWarning>
        <BrandingProvider value={b}>
          <Providers>{children}</Providers>
        </BrandingProvider>
      </body>
    </html>
  );
}
