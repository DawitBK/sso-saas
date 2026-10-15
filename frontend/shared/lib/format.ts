/** "3d 4h", "12m", "45s": a length of time for people, from seconds. */
export function formatDuration(totalSeconds: number): string {
  const s = Math.max(0, Math.round(totalSeconds));
  if (s < 60) return `${s}s`;
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** "just now", "12 minutes ago", "3 days ago". `now` is injectable so it can be tested. */
export function timeAgo(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return 'unknown';
  const seconds = Math.round((now - t) / 1000);
  if (seconds < 5) return 'just now';
  if (seconds < 0) return 'in the future';
  const unit = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'} ago`;
  if (seconds < 60) return unit(seconds, 'second');
  if (seconds < 3600) return unit(Math.floor(seconds / 60), 'minute');
  if (seconds < 86400) return unit(Math.floor(seconds / 3600), 'hour');
  return unit(Math.floor(seconds / 86400), 'day');
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}
