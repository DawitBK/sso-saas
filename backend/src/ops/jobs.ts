/**
 * What the background jobs have been doing, for the console's System page.
 *
 * SSO runs two timers inside the process (the hourly purge of expired artifacts, sessions and old sign-in records, and the
 * half-hourly Active Directory group re-check). They log their own failures, but a log nobody is reading is not a signal: a purge that
 * has been failing for a week fills the database, and an AD re-check that has stopped means a removed person keeps access. This
 * keeps the last outcome of each so the System page can show "last ran 12 minutes ago, ok" or "failing since Tuesday".
 */
export interface JobStatus {
  name: string;
  /** How often it is meant to run, in seconds (so the page can say "overdue"). */
  everySeconds: number;
  lastRunAt: string | null;
  lastOkAt: string | null;
  /** The failure's class and message, never a stack, query or connection string. */
  lastError: string | null;
  runs: number;
  failures: number;
  /** It has not started for more than twice its interval (a stopped timer, or a run that never ends). */
  overdue: boolean;
}

import { pool } from '../db/pool.js';

const jobs = new Map<string, JobStatus>();

export function declareJob(name: string, everySeconds: number): void {
  if (!jobs.has(name)) jobs.set(name, { name, everySeconds, lastRunAt: null, lastOkAt: null, lastError: null, runs: 0, failures: 0, overdue: false });
}

function safeMessage(err: unknown): string {
  const e = err as { name?: string; code?: string; message?: string };
  // A Postgres error message can name the host, database and role; keep the class and the SQLSTATE only.
  return [e?.name ?? 'Error', e?.code ? `(${e.code})` : ''].filter(Boolean).join(' ');
}

/** Run `fn`, record the outcome, and rethrow nothing: a job's failure is data here, and the caller already logs it. */
export async function trackJob(name: string, fn: () => Promise<void>): Promise<void> {
  const job = jobs.get(name);
  if (!job) throw new Error(`job "${name}" was not declared`);
  job.runs += 1;
  job.lastRunAt = new Date().toISOString();
  try {
    await fn();
    job.lastOkAt = job.lastRunAt;
    job.lastError = null;
  } catch (err) {
    job.failures += 1;
    job.lastError = safeMessage(err);
    throw err;
  }
}

export function listJobs(now: number = Date.now()): JobStatus[] {
  return [...jobs.values()].map((j) => ({ ...j, overdue: j.lastRunAt !== null && now - new Date(j.lastRunAt).getTime() > j.everySeconds * 2000 }));
}

/** Test hook. */
export function resetJobs(): void {
  jobs.clear();
}

/**
 * Run `fn` only if no other SSO process is running the same job right now (a Postgres session advisory lock keyed on the job name), and
 * skip silently otherwise. With one process this always runs. With two processes behind the same database it keeps the periodic sweeps from
 * doubling up: the purge, the Active Directory re-check and the audit-chain verification each do real work that one run is enough for.
 * (The notification retry does not need it: it claims rows with FOR UPDATE SKIP LOCKED.)
 */
export async function runExclusive(name: string, fn: () => Promise<void>): Promise<boolean> {
  const client = await pool.connect();
  let locked = false;
  try {
    const { rows } = await client.query<{ ok: boolean }>('SELECT pg_try_advisory_lock(hashtext($1)::bigint) AS ok', [`idp-job:${name}`]);
    locked = Boolean(rows[0]?.ok);
    if (!locked) return false;
    await fn();
    return true;
  } finally {
    if (locked) await client.query('SELECT pg_advisory_unlock(hashtext($1)::bigint)', [`idp-job:${name}`]).catch(() => undefined);
    client.release();
  }
}
