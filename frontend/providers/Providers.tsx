'use client';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { Toaster } from 'react-hot-toast';
import { useThemeStore } from '../state/theme.store';
import { ServiceWorkerRegistration } from '../shared/components/ServiceWorkerRegistration';
import { PwaInstallProvider } from '../shared/hooks/usePwaInstall';

const ThemeSync = () => {
  const { theme } = useThemeStore();

  useEffect(() => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
  }, [theme]);

  return null;
};

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: 1,
            refetchOnWindowFocus: false,
            staleTime: 30_000,
            gcTime: 5 * 60_000,
          },
          mutations: {
            retry: 0,
          },
        },
      }),
  );

  return (
    <PwaInstallProvider>
      <QueryClientProvider client={queryClient}>
        <ThemeSync />
        <ServiceWorkerRegistration />
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              fontFamily: 'ui-sans-serif',
              fontSize: '14px',
              borderRadius: '10px',
            },
            success: { iconTheme: { primary: '#059669', secondary: '#d1fae5' } },
            error: { iconTheme: { primary: '#dc2626', secondary: '#fee2e2' } },
          }}
        />
        {children}
      </QueryClientProvider>
    </PwaInstallProvider>
  );
}
