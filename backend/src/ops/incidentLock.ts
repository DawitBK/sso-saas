/**
 * The incident lock: read-only containment shared by SSO, GMS and DMS (each has its own copy of this logic; keep them in step).
 *
 * A lock is a FILE whose path comes from `INCIDENT_LOCK_FILE`. While the file exists, every state-changing request (POST, PUT, PATCH, DELETE) is answered
 * 403 `INCIDENT_READ_ONLY`, except sign-in and sign-out, health and the licence routes (the same allowlist the licence's read-only state uses,
 * licenses/guard.ts); reads keep working. Unset path = the feature is off (development and tests). The file holds a small JSON object
 * `{ at, reason, kind }` and NO secret.
 *
 * It is a file, not a database row, on purpose: the out-of-process watcher (not part of this edition) can create it when every application is down or
 * compromised, and the owner removes it from a terminal (`tamper.cjs clear`), never through the web. The stat result is cached for three seconds so the guard
 * costs one `stat` per three seconds, not one per request. A path that cannot be read for any reason other than "does not exist" counts as NOT locked
 * (failing open: a broken disk must not turn into a locked-out platform), and is logged once.
 */
import fs from 'node:fs';
import { logger } from '../logging/logger.js';

export interface IncidentLockInfo {
  at: string | null;
  reason: string | null;
  kind: string | null;
}

export const INCIDENT_READ_ONLY_MESSAGE = 'A security incident is being handled; the system is read-only. Contact the owner.';

const CACHE_MS = 3000;
const cache = new Map<string, { at: number; value: IncidentLockInfo | null }>();
let warned = false;

/** Parse the lock file body. A body that is not JSON still means "locked" (someone created the file by hand): the fields are then null. */
export function parseLockBody(body: string): IncidentLockInfo {
  try {
    const j = JSON.parse(body) as Record<string, unknown>;
    const s = (v: unknown, max: number): string | null => (typeof v === 'string' && v ? v.slice(0, max) : null);
    return { at: s(j.at, 40), reason: s(j.reason, 300), kind: s(j.kind, 100) };
  } catch {
    return { at: null, reason: null, kind: null };
  }
}

/** The lock's content, or null when there is no lock. `file` empty or unset = feature off = null. Cached for ~3 s per path. */
export function readIncidentLock(file: string | undefined | null, nowMs: number = Date.now()): IncidentLockInfo | null {
  const path = (file ?? '').trim();
  if (!path) return null;
  const hit = cache.get(path);
  if (hit && nowMs - hit.at < CACHE_MS && nowMs >= hit.at) return hit.value;
  let value: IncidentLockInfo | null = null;
  try {
    const stat = fs.statSync(path);
    if (stat.isFile()) {
      let body = '';
      try {
        body = fs.readFileSync(path, 'utf8').slice(0, 4096);
      } catch {
        /* exists but unreadable: still locked */
      }
      value = parseLockBody(body);
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT' && code !== 'ENOTDIR' && !warned) {
      warned = true;
      logger.warn({ code }, '[idp:incident] the incident lock path could not be checked; treating it as not locked');
    }
  }
  cache.set(path, { at: nowMs, value });
  return value;
}

/** Create the lock if it does not exist. Never overwrites (the first reason stays). Returns true when this call created it. */
export function writeIncidentLock(file: string, info: { reason: string; kind: string }): boolean {
  const path = file.trim();
  if (!path) return false;
  const body = `${JSON.stringify({ at: new Date().toISOString(), reason: info.reason.slice(0, 300), kind: info.kind.slice(0, 100) })}\n`;
  try {
    fs.mkdirSync(requireDir(path), { recursive: true });
    fs.writeFileSync(path, body, { flag: 'wx' });
    cache.delete(path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') return false;
    throw err;
  }
}

function requireDir(p: string): string {
  const i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return i > 0 ? p.slice(0, i) : '.';
}

/**
 * In-process lock for when containment is on but no INCIDENT_LOCK_FILE is configured: it lasts until this process restarts (a file does not).
 * Used only by this process's own incident response; the guard asks activeIncidentLock, which looks at both.
 */
let memoryLock: IncidentLockInfo | null = null;
export function setMemoryIncidentLock(info: { reason: string; kind: string }): void {
  memoryLock ??= { at: new Date().toISOString(), reason: info.reason.slice(0, 300), kind: info.kind.slice(0, 100) };
}

/** The lock that applies right now: the file's, else the in-process one, else null. */
export function activeIncidentLock(file: string | undefined | null, nowMs: number = Date.now()): IncidentLockInfo | null {
  return readIncidentLock(file, nowMs) ?? memoryLock;
}

/** Test hook. */
export function resetIncidentLockCache(): void {
  cache.clear();
  warned = false;
  memoryLock = null;
}
