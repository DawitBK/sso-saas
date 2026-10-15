'use client';

import { useEffect } from 'react';
import { apiPath } from '@shared/apiPath';

export function ServiceWorkerRegistration() {
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;

    // Registered in every environment, including `next dev` — sw.js caches
    // `_next/static/*` with stale-while-revalidate (not cache-first), which
    // self-heals within one reload even against dev's stable, unhashed chunk
    // filenames. See sw.js for why this is safe without an environment check.
    navigator.serviceWorker.register(apiPath('/sw.js')).catch(() => undefined);
  }, []);

  return null;
}
