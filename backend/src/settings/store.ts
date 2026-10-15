/**
 * Platform settings at run time: a database-backed override on top of the defaults in settings/registry.ts.
 *
 * READS ARE SYNCHRONOUS. A setting is read from inside code that cannot wait (oidc-provider's token lifetime callbacks must be
 * plain synchronous functions; the lockout check runs in the sign-in path), so every value lives in an in-memory snapshot that is
 * loaded at start, refreshed every few seconds and replaced the moment this process writes one. Another process picks a change up
 * within REFRESH_MS.
 *
 * FAILS SAFE. If the table cannot be read (database blip, migration 017 not applied yet), the last good snapshot stays in force and
 * the defaults apply on a cold start: a settings problem must never stop a sign-in. A stored value that no longer validates (the
 * limits were tightened in a later release) is ignored with a warning and the default is used.
 */
import { pool } from '../db/pool.js';
import { logger } from '../logging/logger.js';
import { parseSettingValue, settingDef, SETTINGS, type SettingDef, type SettingValue } from './registry.js';

const REFRESH_MS = 10_000;

interface Stored {
  value: SettingValue;
  updatedAt: string;
  updatedBy: string;
}

let snapshot = new Map<string, Stored>();
let timer: NodeJS.Timeout | null = null;
let appIdsProvider: () => string[] = () => [];

/** The launcher ids the `apps` type validates against (supplied by portal/catalog.ts's registry at start, avoiding an import cycle). */
export function setAppIdsProvider(fn: () => string[]): void {
  appIdsProvider = fn;
}

export function currentAppIds(): string[] {
  return appIdsProvider();
}

function readDefault(def: SettingDef): SettingValue {
  return def.defaultValue();
}

/** The effective value: a stored override if there is one, else the default. */
export function getSetting<T extends SettingValue = SettingValue>(key: string): T {
  const def = settingDef(key);
  if (!def) throw new Error(`Unknown setting "${key}"`);
  const stored = snapshot.get(key);
  return (stored ? stored.value : readDefault(def)) as T;
}

export const getNumber = (key: string): number => getSetting<number>(key);
export const getBool = (key: string): boolean => getSetting<boolean>(key);
export const getString = (key: string): string => getSetting<string>(key);
export const getList = (key: string): string[] => getSetting<string[]>(key);

export interface SettingState {
  def: SettingDef;
  value: SettingValue;
  defaultValue: SettingValue;
  /** 'default' = nothing stored; 'stored' = an administrator changed it. */
  source: 'default' | 'stored';
  updatedAt: string | null;
  updatedBy: string | null;
}

export function listSettingStates(): SettingState[] {
  return SETTINGS.map((def) => {
    const stored = snapshot.get(def.key);
    return {
      def,
      value: stored ? stored.value : readDefault(def),
      defaultValue: readDefault(def),
      source: stored ? 'stored' : 'default',
      updatedAt: stored?.updatedAt ?? null,
      updatedBy: stored?.updatedBy ?? null,
    };
  });
}

/** Re-read every stored override. Never throws: on failure the previous snapshot stays. */
export async function loadSettings(): Promise<void> {
  try {
    const { rows } = await pool.query<{ key: string; value: unknown; updated_at: Date; updated_by: string }>(
      'SELECT key, value, updated_at, updated_by FROM idp_settings',
    );
    const next = new Map<string, Stored>();
    for (const r of rows) {
      const def = settingDef(r.key);
      if (!def) continue; // a key from a newer release, or one that was retired
      const parsed = parseSettingValue(def, r.value, appIdsProvider());
      if (!parsed.ok) {
        logger.warn({ key: r.key, reason: parsed.error }, '[idp:settings] stored value no longer valid; using the default');
        continue;
      }
      next.set(r.key, { value: parsed.value, updatedAt: new Date(r.updated_at).toISOString(), updatedBy: r.updated_by });
    }
    snapshot = next;
  } catch (err) {
    const code = (err as { code?: string })?.code;
    if (code === '42P01') {
      logger.warn('[idp:settings] idp_settings does not exist yet (migration 017 not applied); using defaults');
    } else {
      logger.warn({ err }, '[idp:settings] could not read settings; keeping the last known values');
    }
  }
}

export function startSettingsRefresh(): void {
  if (timer) return;
  timer = setInterval(() => { void loadSettings(); }, REFRESH_MS);
  timer.unref();
}

export function stopSettingsRefresh(): void {
  if (timer) clearInterval(timer);
  timer = null;
}

export interface SettingChange {
  key: string;
  before: SettingValue;
  after: SettingValue;
}

/** Validates, stores and applies one value. `actor` is the administrator's email, or 'platform' (the platform administrator stays anonymous). */
export async function setSetting(key: string, raw: unknown, actor: string): Promise<{ ok: true; change: SettingChange } | { ok: false; error: string }> {
  const def = settingDef(key);
  if (!def) return { ok: false, error: 'Unknown setting.' };
  const parsed = parseSettingValue(def, raw, appIdsProvider());
  if (!parsed.ok) return parsed;
  const before = getSetting(key);
  await pool.query(
    `INSERT INTO idp_settings (key, value, updated_at, updated_by) VALUES ($1, $2::jsonb, NOW(), $3)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW(), updated_by = EXCLUDED.updated_by`,
    [key, JSON.stringify(parsed.value), actor],
  );
  snapshot.set(key, { value: parsed.value, updatedAt: new Date().toISOString(), updatedBy: actor });
  return { ok: true, change: { key, before, after: parsed.value } };
}

/** Removes the override so the default applies again. */
export async function resetSetting(key: string): Promise<{ ok: true; change: SettingChange } | { ok: false; error: string }> {
  const def = settingDef(key);
  if (!def) return { ok: false, error: 'Unknown setting.' };
  const before = getSetting(key);
  await pool.query('DELETE FROM idp_settings WHERE key = $1', [key]);
  snapshot.delete(key);
  return { ok: true, change: { key, before, after: readDefault(def) } };
}

/** Test hook: replace the in-memory snapshot. */
export function __setSnapshotForTests(entries: Record<string, SettingValue>): void {
  snapshot = new Map(Object.entries(entries).map(([k, value]) => [k, { value, updatedAt: new Date(0).toISOString(), updatedBy: 'test' }]));
}
