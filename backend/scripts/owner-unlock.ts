/**
 * Owner verification: clear the lockout after too many wrong attempts (for example when someone with a stolen session failed on purpose).
 *   npm run owner:unlock      (production: node scripts/run-with-env.cjs production npx tsx scripts/owner-unlock.ts)
 * Needs the platform vault password, typed at the terminal. It clears the counters only; it does not change any answer, code or setting.
 */
import '../src/config.js';
import { pool } from '../src/db/pool.js';
import { ownerAudit } from '../src/owner/audit.js';
import { clearLock, lockStatus } from '../src/owner/limiter.js';
import { askHidden, requireTerminal, vaultPasswordIsCorrect } from './lib/terminal.js';

async function main(): Promise<void> {
  requireTerminal();
  const before = await lockStatus();
  console.log(`\n  Currently ${before.locked ? `LOCKED, ${before.retryAfterSeconds} s left` : 'not locked'} (level ${before.level}, ${before.failures} failure(s) counted).`);
  if (!(await vaultPasswordIsCorrect(await askHidden('  Vault password: ')))) {
    console.error('\n  Wrong vault password (the vault counted it). Nothing was changed.\n');
    process.exit(1);
  }
  await clearLock();
  await ownerAudit('unlocked', 'ok', { detail: { wasLocked: before.locked, level: before.level } });
  console.log('\n  The lockout and the failure count are cleared.\n');
}

main()
  .catch((e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
