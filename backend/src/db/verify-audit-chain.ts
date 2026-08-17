/**
 * Standalone CLI check of the idp_admin_audit hash chain (see
 * src/admin/audit.ts's verifyAuditChain — also reachable live via
 * GET /admin/audit/verify in the admin console).
 *
 * Run standalone:  npm run audit:verify
 */

import { verifyAuditChain } from '../admin/audit.js';
import { pool } from './pool.js';

async function main(): Promise<void> {
  const result = await verifyAuditChain();
  // eslint-disable-next-line no-console
  console.log(`[idp:audit] ${result.valid ? 'VALID' : 'BROKEN'} — ${result.message}`);
  if (!result.valid) {
    // eslint-disable-next-line no-console
    console.error(`[idp:audit] broken at sequence_number=${result.brokenAtSequence}`);
  }
  await pool.end();
  process.exit(result.valid ? 0 : 1);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
