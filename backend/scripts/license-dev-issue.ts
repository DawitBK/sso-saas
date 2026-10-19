/**
 * license-dev-issue.ts: put licence rows into THIS database for development and the mirror (docs/operations/PLATFORM-LICENSING.md section 9.4).
 *
 * Dev and the mirror have no platform administrator, so Admin > Licences cannot be used there; and with LICENSE_REQUIRED true (the mirror runs in
 * production mode) a system with no licence is unusable. This writes the rows directly, with an event row each, the same shape the console writes.
 *
 *   dev:     I_UNDERSTAND_THIS_ISSUES_LICENCES=idp       npx tsx scripts/license-dev-issue.ts --customer "Example Corp" [--expires never|date] [--modes sso,standalone] [--systems sso,gms,dms]
 *   mirror:  I_UNDERSTAND_THIS_ISSUES_LICENCES=idpprod   node scripts/run-with-env.cjs mirror npx tsx scripts/license-dev-issue.ts ...
 *
 * The variable must name the database it is about to write to. For the LIVE server the owner issues licences in the console (or signs offline);
 * this script is not part of that procedure.
 */
import { pool } from '../src/db/pool.js';
import { LICENSE_SYSTEMS, isLicenseSystem, type LicenseSystem } from '../src/licenses/catalog.js';
import { findLicense, highestVersionEver, insertEvent, insertLicense, updateLicense } from '../src/licenses/repository.js';
import { validateLicenseInput } from '../src/licenses/validation.js';

const args = process.argv.slice(2);
const arg = (name: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const { rows: dbRows } = await pool.query<{ db: string }>('SELECT current_database() AS db');
const db = dbRows[0].db;
if (process.env.I_UNDERSTAND_THIS_ISSUES_LICENCES !== db) {
  console.error(`Refusing: set I_UNDERSTAND_THIS_ISSUES_LICENCES=${db} to confirm you mean to write licences into the database "${db}".`);
  process.exit(2);
}

const systems = (arg('systems') ?? LICENSE_SYSTEMS.join(',')).split(',').map((s) => s.trim()).filter(Boolean);
const bad = systems.filter((s) => !isLicenseSystem(s));
if (bad.length) {
  console.error(`Unknown system: ${bad.join(', ')} (use sso, gms, dms).`);
  process.exit(2);
}
const expires = arg('expires') ?? 'never';
const modes = (arg('modes') ?? 'sso').split(',').filter(Boolean);

for (const system of systems as LicenseSystem[]) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [`license:${system}`]);
    const existing = await findLicense(system, client, true);
    const checked = validateLicenseInput(
      system,
      { customer: arg('customer') ?? existing?.customer ?? 'Development', expiresAt: expires === 'never' ? null : expires, modes },
      existing,
    );
    if (!checked.ok) throw new Error(checked.details.map((d) => `${d.field}: ${d.message}`).join('; '));
    const version = Math.max(existing?.version ?? 0, await highestVersionEver(system, client)) + 1;
    const write = { system, ...checked.value, version, actor: 'dev-issue' };
    const license = existing ? await updateLicense(write, client) : await insertLicense(write, client);
    await insertEvent({ system, action: existing ? 'update' : 'create', actor: 'dev-issue', version, before: existing, after: license }, client);
    await client.query('COMMIT');
    console.log(`${system}: licence v${version} for "${license.customer}", expires ${license.expiresAt ?? 'never'}, modes ${license.modes.join('+')}`);
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(`${system}: ${(err as Error).message}`);
    process.exitCode = 1;
  } finally {
    client.release();
  }
}
await pool.end();
