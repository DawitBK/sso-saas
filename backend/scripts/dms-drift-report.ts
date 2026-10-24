/**
 * READ-ONLY report of where SSO and DMS disagree about people. Changes nothing, anywhere.
 *
 * There is no background reconciliation between the two systems: SSO's disabled flag reaches
 * DMS only as a best-effort backchannel logout at the moment of the click, and DMS keeps its
 * own is_active. This script is how an administrator checks, on demand, that nothing was
 * missed (for example the logout notification could not reach DMS that day).
 *
 * For every ordinary SSO account (the platform administrator is excluded here and is
 * invisible to the DMS endpoint anyway) it asks DMS's internal status API and prints:
 *   DISABLED-IN-SSO / ACTIVE-IN-DMS   the account is off in SSO but DMS still lists it active.
 *                                     SSO sign-in is refused, so only a session that survived
 *                                     the disable (the notification failed) or DMS's own
 *                                     password-less login (LOCAL_JWT_MOCK) can still use it.
 *                                     Fix: force-logout the user in DMS, then deactivate there.
 *   ACTIVE-IN-SSO / INACTIVE-IN-DMS   informational: DMS-side deactivation is deliberate and
 *                                     wins (SSO cannot re-activate a DMS account).
 * Exit code: 0 clean, 1 disagreements found, 2 DMS could not be queried.
 *
 * Usage (from backend). Mirror / production MUST go through run-with-env.cjs or this
 * silently targets the DEV database:
 *   Dev:  npx tsx scripts/dms-drift-report.ts
 *   Prod: node scripts/run-with-env.cjs production tsx scripts/dms-drift-report.ts
 */
import { IDP_CONFIG } from '../src/config.js';
import { pool } from '../src/db/pool.js';
import { getDmsUserStatusByEmail } from '../src/admin/dms-internal-client.js';

async function main(): Promise<number> {
  if (!IDP_CONFIG.dmsInternalApiKey) {
    console.error('DMS_INTERNAL_API_KEY is not configured - cannot query DMS.');
    return 2;
  }
  const { rows } = await pool.query<{ email: string; is_active: boolean }>(
    'SELECT email, is_active FROM idp_users WHERE NOT is_platform_admin ORDER BY email',
  );
  let disagreements = 0;
  let informational = 0;
  let unreachable = 0;
  for (const user of rows) {
    try {
      const status = await getDmsUserStatusByEmail(IDP_CONFIG.dmsDefaultTenant, user.email);
      if (!status.exists) continue;
      if (!user.is_active && status.active) {
        disagreements++;
        console.log(`DISABLED-IN-SSO / ACTIVE-IN-DMS   ${user.email}`);
      } else if (user.is_active && status.active === false) {
        informational++;
        console.log(`ACTIVE-IN-SSO / INACTIVE-IN-DMS   ${user.email}`);
      }
    } catch (err) {
      unreachable++;
      if (unreachable === 1) console.error(`DMS query failed: ${(err as Error).message}`);
    }
  }
  console.log(
    `\nChecked ${rows.length} SSO accounts: ${disagreements} disagreement(s), ${informational} informational, ${unreachable} could not be checked.`,
  );
  if (unreachable > 0) return 2;
  return disagreements > 0 ? 1 : 0;
}

main()
  .then((code) => pool.end().finally(() => process.exit(code)))
  .catch((err) => {
    console.error(err);
    pool.end().finally(() => process.exit(2));
  });
