/**
 * export-directory.ts: writes the company directory (who has an SSO account) to a file the DMS data compiler can read.
 *
 * Why: a department's questionnaire often lists people by name with no e-mail address (Finance's did, for all 29 people), and the address is the person's DMS login. An address is never
 * invented: it is looked up here, in the accounts that already exist (most staff were imported from GMS), by name, with a confidence level (DMS/backend/scripts/lib/collectedCleaning.ts).
 *
 * Read-only: one SELECT, no writes. The file holds names and work e-mail addresses, so it is NOT committed (DMS/.gitignore lists it) and is not for sharing.
 * The platform administrator is never included (the same rule as every console list).
 *
 *   npm run data:export-directory                (from SSO/backend; development or mirror database, whichever the environment points at)
 *   COLLECTED_DIRECTORY_FILE=... to write somewhere else
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool } from '../src/db/pool.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FILE = process.env.COLLECTED_DIRECTORY_FILE ?? path.resolve(__dirname, '..', '..', '..', 'DMS', 'Collected-Data', '.sso-directory.json');

async function main(): Promise<void> {
  const { rows } = await pool.query<{ email: string; given_name: string; family_name: string; is_active: boolean }>(
    `SELECT email, given_name, family_name, is_active FROM idp_users WHERE NOT is_platform_admin ORDER BY email`,
  );
  const people = rows.map((r) => ({ email: r.email, givenName: r.given_name, familyName: r.family_name, active: r.is_active }));
  fs.writeFileSync(FILE, JSON.stringify({ exportedAt: new Date().toISOString(), people }, null, 1) + '\n');
  console.log(`Wrote ${people.length} people to ${FILE} (not committed: names and work addresses).`);
  await pool.end();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
