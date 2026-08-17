/**
 * Minimal SQL migration runner. Applies every `migrations/*.sql` file once,
 * tracked in `idp_migrations`. Ordered lexicographically (001_, 002_, ...).
 *
 * Run standalone:  npm run db:migrate
 * Also invoked from main.ts on boot in non-production for convenience.
 */

import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from './pool.js';
import { logger } from '../logging/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// src/db -> project root -> migrations
const MIGRATIONS_DIR = path.resolve(__dirname, '../../migrations');

export async function runMigrations(): Promise<string[]> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS idp_migrations (
      name       TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);

  const files = (await readdir(MIGRATIONS_DIR))
    .filter((f) => f.endsWith('.sql'))
    .sort();

  const { rows } = await pool.query<{ name: string }>('SELECT name FROM idp_migrations');
  const applied = new Set(rows.map((r) => r.name));
  const newlyApplied: string[] = [];

  for (const file of files) {
    if (applied.has(file)) continue;
    const sql = await readFile(path.join(MIGRATIONS_DIR, file), 'utf-8');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO idp_migrations (name) VALUES ($1)', [file]);
      await client.query('COMMIT');
      newlyApplied.push(file);
      logger.info({ file }, '[idp:migrate] applied');
    } catch (err) {
      await client.query('ROLLBACK');
      throw new Error(`Migration ${file} failed: ${(err as Error).message}`);
    } finally {
      client.release();
    }
  }
  return newlyApplied;
}

// Allow `node dist/db/migrate.js` / `tsx src/db/migrate.ts` to run directly.
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('migrate.ts') || process.argv[1]?.endsWith('migrate.js')) {
  runMigrations()
    .then((applied) => {
      // eslint-disable-next-line no-console
      console.log(applied.length ? `Applied ${applied.length} migration(s).` : 'No pending migrations.');
      return pool.end();
    })
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error(err);
      process.exit(1);
    });
}
