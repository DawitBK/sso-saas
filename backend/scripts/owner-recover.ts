/**
 * Owner verification: enrol again (lost phone, lost questions, a store that cannot be opened, recovery codes running out). Run it yourself, at a
 * terminal on the SSO server.
 *
 *   npm run owner:recover
 *   node scripts/run-with-env.cjs production npx tsx scripts/owner-recover.ts
 *
 * You prove it is you with EITHER the platform vault password (the one `platform-vault.ts set` chose; leave the prompt empty to skip) OR one unused
 * offline recovery code. Then you go through the same steps as `owner:enroll`; the old questions, authenticator and recovery codes stop working at once.
 * A missing key file is created again; a store sealed by a different key is replaced (that is the "lost the key file" repair, and it needs the vault password).
 */
import '../src/config.js';
import fs from 'node:fs';
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { ownerAudit } from '../src/owner/audit.js';
import { findOwnerAccountId } from '../src/owner/enrol.js';
import { createKeyFile, loadStoreKeys } from '../src/owner/seal.js';
import { readStore, spendRecoveryCode } from '../src/owner/store.js';
import { chooseKeyFile, refuseInsideRepo, runEnrolment } from './lib/enrolFlow.js';
import { askHidden, requireTerminal, vaultPasswordIsCorrect } from './lib/terminal.js';

async function main(): Promise<void> {
  requireTerminal();
  const owner = await findOwnerAccountId();
  if ('problem' in owner) {
    console.error(`\n  ${owner.problem}\n`);
    process.exit(1);
  }
  const store = await readStore();
  if (store.state === 'none') {
    console.error('\n  Nothing is set up yet. Use "npm run owner:enroll".\n');
    process.exit(1);
  }

  let via: 'vault' | 'recovery_code';
  const vault = await askHidden('  Vault password (press ENTER to use a recovery code instead): ');
  if (vault) {
    if (!(await vaultPasswordIsCorrect(vault))) {
      console.error('\n  Wrong vault password (the vault counted it). Nothing was changed.\n');
      process.exit(1);
    }
    via = 'vault';
  } else {
    if (store.state !== 'ok') {
      console.error('\n  The store cannot be opened, so a recovery code cannot be checked. Use the vault password.\n');
      process.exit(1);
    }
    const code = await askHidden('  One unused recovery code: ');
    const result = await spendRecoveryCode(store.keys, store.doc, code);
    if (result !== 'ok') {
      console.error(`\n  ${result === 'used' ? 'That recovery code was already used.' : 'That is not a valid recovery code.'} Nothing was changed.\n`);
      process.exit(1);
    }
    via = 'recovery_code';
  }

  const file = await chooseKeyFile(IDP_CONFIG.ownerStoreKeyFile);
  refuseInsideRepo(file);
  let keys;
  if (fs.existsSync(file)) {
    keys = loadStoreKeys(file);
  } else if (via === 'vault') {
    keys = createKeyFile(file);
    console.log('  The key file was missing: created a new one with restrictive permissions.');
  } else {
    console.error('\n  The key file is missing; only the vault password can repair that. Nothing was changed.\n');
    process.exit(1);
  }
  if (!IDP_CONFIG.ownerStoreKeyFile) console.log(`\n  ADD THIS LINE to this environment's env file, then restart SSO:\n    OWNER_STORE_KEY_FILE=${file}`);
  await ownerAudit('recovery_started', 'info', { detail: { via } });
  await runEnrolment(keys, owner.id);
  await ownerAudit('recovered', 'ok', { detail: { via } });
}

main()
  .catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
