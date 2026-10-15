/**
 * ack-dev-audit-history.ts: acknowledge the audit-chain breaks that already exist in the DEVELOPMENT database (dev only).
 *
 * The dev `idp` database holds ten entries from July 2026, written before hash version 2, that no longer recompute under the current dev
 * AUDIT_HMAC_SECRET. They are development data and nobody will repair them; left open they keep the System page on "Needs attention" and the
 * Audit page on "CHAIN BROKEN" for ever, which would hide a real break on this machine. This records one acknowledgement for each, with the reason,
 * so a NEW break still shows. It goes through the same function the console uses (admin/audit.ts#acknowledgeChainBreak), so each acknowledgement
 * is pinned to its row and appended to the chain.
 *
 * Refuses on production and on the mirror (IDP_CONFIG.isProd): there, a break is something to investigate, and only the platform administrator
 * acknowledges it, in the console.
 */
import type { Request } from 'express';
import { pool } from '../src/db/pool.js';
import { IDP_CONFIG } from '../src/config.js';
import { acknowledgeChainBreak, verifyAuditChain } from '../src/admin/audit.js';

if (IDP_CONFIG.isProd) {
  console.error('Refusing: dev only. Acknowledge a break in the console, as the platform administrator.');
  process.exit(2);
}

const req = { get: () => 'ack-dev-audit-history', ip: '127.0.0.1', headers: {}, socket: { remoteAddress: '127.0.0.1' } } as unknown as Request;
const reason = 'Development database: an entry written in July 2026 before hash version 2; it does not recompute under the current dev AUDIT_HMAC_SECRET. Dev data only, reviewed 2026-10-11.';

let acknowledged = 0;
for (;;) {
  const result = await verifyAuditChain();
  const next = result.breaks.find((b) => !b.acknowledged && b.acknowledgeable);
  if (!next) {
    console.log(result.valid ? `The chain verifies (${result.acknowledgedBreaks} acknowledged break(s) on record).` : `Still ${result.openBreaks} break(s) that cannot be acknowledged here; see npm run audit:verify.`);
    break;
  }
  await acknowledgeChainBreak(req, 'dev-seed@local', { sequenceNumber: next.sequenceNumber, kind: next.kind, reason });
  acknowledged += 1;
}
console.log(`Acknowledged ${acknowledged} break(s).`);
await pool.end();
