'use client';

import { useEffect, useState } from 'react';

/** The current time in milliseconds (null until the first tick, so a countdown shows nothing rather than a wrong number), refreshed every `intervalMs` while `active` (a countdown). Stops ticking when not needed. */
export function useNow(active: boolean, intervalMs = 1000): number | null {
  // `null` until mounted, so the server render and the first client render agree; the first tick happens on the next frame.
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    if (!active) return;
    const first = window.setTimeout(() => setNow(Date.now()), 0);
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(id);
    };
  }, [active, intervalMs]);
  return now;
}
