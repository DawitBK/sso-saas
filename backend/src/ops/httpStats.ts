/**
 * Request counts and latency for the Prometheus endpoint (ops/prometheus.ts), kept in this process.
 *
 * Labels are deliberately coarse: the status class (2xx, 3xx, ...) and an "area" taken from the first path segment against a fixed list.
 * A label made from the raw URL (a user id, a session uid) would give a scraper an unbounded number of series.
 */
import type { NextFunction, Request, Response } from 'express';

export const LATENCY_BUCKETS_SECONDS = [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10] as const;

const AREAS: Record<string, string> = {
  api: 'api',
  authorize: 'oidc',
  token: 'oidc',
  me: 'oidc',
  jwks: 'oidc',
  '.well-known': 'oidc',
  session: 'oidc',
  portal: 'portal',
  interaction: 'interaction',
  bridge: 'bridge',
  health: 'health',
  internal: 'internal',
  metrics: 'metrics',
};

export function areaOf(path: string): string {
  const first = path.split('?')[0].split('/').filter(Boolean)[0] ?? '';
  return Object.prototype.hasOwnProperty.call(AREAS, first) ? AREAS[first] : 'other';
}

export function statusClass(status: number): string {
  return `${Math.floor(status / 100)}xx`;
}

interface Series {
  count: number;
  sum: number;
  /** Cumulative bucket counts, one per LATENCY_BUCKETS_SECONDS entry, as Prometheus histograms expect. */
  buckets: number[];
}

const series = new Map<string, Series>();

export function observeRequest(area: string, status: number, seconds: number): void {
  const k = `${area}|${statusClass(status)}`;
  let s = series.get(k);
  if (!s) {
    s = { count: 0, sum: 0, buckets: LATENCY_BUCKETS_SECONDS.map(() => 0) };
    series.set(k, s);
  }
  const target = s;
  target.count += 1;
  target.sum += seconds;
  LATENCY_BUCKETS_SECONDS.forEach((le, i) => {
    if (seconds <= le) target.buckets[i] += 1;
  });
}

export interface HttpSeries {
  area: string;
  statusClass: string;
  count: number;
  sum: number;
  buckets: number[];
}

export function snapshotHttpStats(): HttpSeries[] {
  return [...series.entries()].map(([k, s]) => {
    const [area, cls] = k.split('|');
    return { area, statusClass: cls, count: s.count, sum: s.sum, buckets: [...s.buckets] };
  });
}

/** Express middleware: record every finished response. */
export function httpStatsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const started = process.hrtime.bigint();
  const area = areaOf(req.originalUrl || req.url);
  res.once('finish', () => {
    observeRequest(area, res.statusCode, Number(process.hrtime.bigint() - started) / 1e9);
  });
  next();
}

/** Test hook. */
export function resetHttpStats(): void {
  series.clear();
}
