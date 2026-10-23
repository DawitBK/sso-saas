/**
 * Owner verification: what is set up, with NO secret in the output.
 *   npm run owner:status      (production: node scripts/run-with-env.cjs production npx tsx scripts/owner-status.ts)
 * Needs no terminal and shows no answer, code, address, secret or key; safe to paste into a support request.
 */
import '../src/config.js';
import fs from 'node:fs';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { recentOwnerAudit } from '../src/owner/audit.js';
import { ownerStatus } from '../src/owner/challenge.js';
import { findOwnerAccountId } from '../src/owner/enrol.js';
import { lockStatus } from '../src/owner/limiter.js';
import { smtpConfigured } from '../src/owner/mailer.js';

async function main(): Promise<void> {
  const owner = await findOwnerAccountId();
  const keyFile = IDP_CONFIG.ownerStoreKeyFile;
  console.log(`\n  database:                   ${new URL(IDP_CONFIG.databaseUrl).pathname.slice(1)}`);
  console.log(`  verification required:      ${IDP_CONFIG.ownerVerificationRequired ? 'yes' : 'no (development setting)'}${IDP_CONFIG.ownerVerificationRequiredExplicit ? ' (set explicitly)' : ''}`);
  console.log(`  key file configured:        ${keyFile ? 'yes' : 'NO (OWNER_STORE_KEY_FILE is not set)'}`);
  console.log(`  key file present:           ${keyFile ? (fs.existsSync(keyFile) ? 'yes' : 'NO') : 'n/a'}`);
  console.log(`  SMTP configured:            ${smtpConfigured() ? 'yes' : 'no (the emailed code is unavailable)'}`);
  if ('problem' in owner) {
    console.log(`  platform administrator:     ${owner.problem}`);
    return;
  }
  const s = await ownerStatus(owner.id);
  console.log(`  enrolled:                   ${s.enrolled ? 'yes' : 'NO'}${s.storeProblem ? `  (store problem: ${s.storeProblem})` : ''}`);
  console.log(`  authenticator:              ${s.authenticator === null ? 'n/a' : s.authenticator ? 'required (enrolled with it)' : 'not used (enrolled without)'}`);
  console.log(`  authenticator for new enrolments: ${IDP_CONFIG.ownerAuthenticatorRequired ? 'required' : 'not required (OWNER_AUTHENTICATOR_REQUIRED=false)'}`);
  console.log(`  emailed code:               ${s.emailAvailable ? 'available' : `unavailable${s.emailUnavailableReason ? ` (${s.emailUnavailableReason})` : ''}`}`);
  console.log(`  recovery codes left:        ${s.recoveryCodesRemaining}${s.recoveryCodesRemaining <= 2 && s.enrolled ? '   <-- low: run owner:recover to make new ones' : ''}`);
  const lock = await lockStatus();
  console.log(`  locked:                     ${lock.locked ? `YES, ${lock.retryAfterSeconds} s left (level ${lock.level}); "npm run owner:unlock" clears it` : 'no'}`);
  console.log('  recent events:');
  for (const r of await recentOwnerAudit(10)) console.log(`    ${r.at}  ${r.event}  ${r.outcome}${r.operation ? `  ${r.operation}` : ''}`);
  console.log('');
}

main()
  .catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
