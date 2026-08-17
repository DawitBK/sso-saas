import type { Metadata, Viewport } from 'next';
import { Providers } from '../providers/Providers';
import { apiPath } from '@shared/apiPath';
import './globals.css';

export const metadata: Metadata = {
  title: 'Example Corp SSO',
  description: 'Example Corp Identity — single sign-on',
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

export const viewport: Viewport = {
  themeColor: '#166534',
};

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

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: NO_FLASH_SCRIPT }} />
      </head>
      <body suppressHydrationWarning>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
