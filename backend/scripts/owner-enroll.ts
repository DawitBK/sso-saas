/**
 * Owner verification: first-time enrolment. Run it yourself, at a terminal, on the SSO server (the owner's own tool, not part of the production package).
 *
 *   npm run owner:enroll                                                     development
 *   node scripts/run-with-env.cjs production npx tsx scripts/owner-enroll.ts production
 *   node scripts/run-with-env.cjs mirror     npx tsx scripts/owner-enroll.ts mirror
 *
 * You choose three security questions and type their answers (hidden), give your mailbox address, set up the phone authenticator and are shown your
 * offline recovery codes once. Nothing is accepted from arguments, environment or pipes, and nothing typed is shown, logged or kept except as hashes and
 * as the sealed store (AES-256-GCM, key file named by OWNER_STORE_KEY_FILE outside the repository).
 * Already enrolled? Use owner:recover (enrol again) or owner:change-email.
 */
import '../src/config.js';
import fs from 'node:fs';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { findOwnerAccountId } from '../src/owner/enrol.js';
import { createKeyFile, loadStoreKeys } from '../src/owner/seal.js';
import { readStore } from '../src/owner/store.js';
import { chooseKeyFile, refuseInsideRepo, runEnrolment } from './lib/enrolFlow.js';
import { requireTerminal } from './lib/terminal.js';

async function main(): Promise<void> {
  requireTerminal();
  const owner = await findOwnerAccountId();
  if ('problem' in owner) {
    console.error(`\n  ${owner.problem}\n`);
    process.exit(1);
  }
  const existing = await readStore();
  if (existing.state !== 'none') {
    console.error('\n  Owner verification is already set up in this database. Use "npm run owner:recover" to enrol again, or "npm run owner:change-email".\n');
    process.exit(1);
  }
  const file = await chooseKeyFile(IDP_CONFIG.ownerStoreKeyFile);
  refuseInsideRepo(file);
  let keys;
  if (fs.existsSync(file)) {
    keys = loadStoreKeys(file);
    console.log('  Using the existing key file.');
  } else {
    keys = createKeyFile(file);
    console.log('  Created a new key file with restrictive permissions. Back it up where only you can reach it: without it the store cannot be opened.');
  }
  if (!IDP_CONFIG.ownerStoreKeyFile) console.log(`\n  ADD THIS LINE to this environment's env file, then restart SSO:\n    OWNER_STORE_KEY_FILE=${file}`);
  await runEnrolment(keys, owner.id);
}

main()
  .catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
