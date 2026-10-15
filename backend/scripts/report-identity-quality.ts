/**
 * report-identity-quality.ts: lists accounts whose e-mail address or name looks wrong (mistyped company domain, no dot in the domain, throw-away address, empty name,
 * possible duplicate person), with the correction it would suggest. READ-ONLY: it never changes an account. An address is a person's sign-in and the key other systems use for them,
 * so the owner decides each one (and corrects it in SSO, DMS and GMS together).
 *
 *   npm run data:quality                  print the report (development, or mirror/production through the launcher)
 *   npm run data:quality -- --csv=out.csv also write a spreadsheet-friendly list (formula-safe)
 *
 * The platform administrator is never included.
 */
import fs from 'node:fs';
import { pool } from '../src/db/pool.js';
import { csvRow } from '../src/http/csv.js';
import { findIdentityProblems, type Identity } from './lib/identityQuality.js';

async function main(): Promise<void> {
  const { rows } = await pool.query<{ email: string; given_name: string; family_name: string; is_active: boolean; source: string }>(
    `SELECT email, given_name, family_name, is_active, source FROM idp_users WHERE NOT is_platform_admin ORDER BY email`,
  );
  const all: Identity[] = rows.map((r) => ({ email: r.email, givenName: r.given_name, familyName: r.family_name, active: r.is_active, source: r.source }));
  const findings = findIdentityProblems(all);
  console.log(`${all.length} accounts checked, ${findings.length} finding(s).\n`);
  const kinds = [...new Set(findings.map((f) => f.kind))];
  for (const kind of kinds) {
    const of = findings.filter((f) => f.kind === kind);
    console.log(`${kind} (${of.length})`);
    for (const f of of) console.log(`  ${f.email.padEnd(46)} ${f.detail}${f.suggestion ? `\n  ${' '.repeat(46)} suggest: ${f.suggestion}` : ''}`);
    console.log('');
  }
  const csvArg = process.argv.find((a) => a.startsWith('--csv='));
  if (csvArg) {
    const lines = [csvRow(['kind', 'email', 'detail', 'suggestion']), ...findings.map((f) => csvRow([f.kind, f.email, f.detail, f.suggestion ?? '']))];
    fs.writeFileSync(csvArg.slice(6), String.fromCharCode(0xfeff) + lines.join('\r\n') + '\r\n');
    console.log(`Wrote ${csvArg.slice(6)}`);
  }
  console.log('Nothing was changed. Correct an address in SSO, DMS and GMS together, after confirming with the person.');
  await pool.end();
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
