/**
 * Removes demo / seed accounts from an SSO database, and nothing else.
 *
 * What counts as seed data (and ONLY this):
 *  - accounts whose email ends in `@edams.local` or `@gms.local` (db:seed:users);
 *  - the two bootstrap administrators `admin@examplecorp.com` and `master@examplecorp.com`
 *    (db:seed:dev), but ONLY while their password is still the one published in the
 *    repository's history (`demo` / `MasterTest#2026!`). If someone has changed it, it is a
 *    real account now and is left alone, and the run says so;
 *  - any further accounts you name with --users=a@x,b@y.
 *
 * What is never touched: the platform administrator (the run REFUSES if one is in the
 * target set), the legacy accounts imported from GMS (bcrypt hashes; the organisation's
 * real staff), and the admin audit trail (immutable and hash-chained). It also REFUSES to
 * leave the admin console without a single administrator.
 *
 * For each removed account: its live sessions and tokens, portal and gateway sessions, its
 * sign-in history, its per-user GMS role grants and office pin, its group memberships, and
 * the access mappings of its personal group (entitlements, GMS role, and, best effort
 * through DMS's internal API, the DMS role mapping).
 *
 * On --execute it writes `cleanup-removed-personal-groups-<time>.json` (in ./logs) naming the
 * removed accounts' personal groups, for DMS/backend/scripts/cleanup-seed-data.ts
 * --personal-groups-file=..., since DMS keys its role mappings on those names.
 *
 * DRY RUN unless --execute; one transaction, so a failure changes nothing. In mirror or
 * production it additionally demands I_UNDERSTAND_THIS_DELETES=<database name>.
 *
 * Usage (from SSO/backend; mirror/production MUST use the launcher or this targets DEV):
 *   npx tsx scripts/cleanup-seed-data.ts
 *   npx tsx scripts/cleanup-seed-data.ts --users=tester@example.com --execute
 *   node scripts/run-with-env.cjs mirror npx tsx scripts/cleanup-seed-data.ts --execute
 */
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { IDP_CONFIG } from '../src/config.js';
import { verifyPassword } from '../src/auth/password.js';
import { putDmsRoleMapping } from '../src/admin/dms-internal-client.js';

const EXECUTE = process.argv.includes('--execute');
const arg = (name: string): string | undefined =>
  process.argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);

/** The two passwords that are public in this repository's history (db:seed:dev, db:seed:users). */
const BOOTSTRAP_ADMINS: { email: string; publicPasswords: string[] }[] = [
  { email: 'admin@examplecorp.com', publicPasswords: ['demo'] },
  { email: 'master@examplecorp.com', publicPasswords: ['MasterTest#2026!'] },
];

async function main() {
  const dbName = new URL(IDP_CONFIG.databaseUrl).pathname.slice(1);
  const nodeEnv = process.env.NODE_ENV ?? 'development';
  if (EXECUTE && (nodeEnv === 'production' || nodeEnv === 'mirror') && process.env.I_UNDERSTAND_THIS_DELETES !== dbName) {
    console.error(`\n  Refusing to DELETE from "${dbName}" (NODE_ENV=${nodeEnv}) without I_UNDERSTAND_THIS_DELETES=${dbName}.\n`);
    process.exit(2);
  }
  const named = (arg('users') ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);

  const c = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await c.connect();
  console.log(`\n  database: ${dbName}   mode: ${EXECUTE ? 'EXECUTE' : 'dry run (nothing is changed)'}`);

  try {
    await c.query('BEGIN');
    const { rows: candidates } = await c.query<{ id: string; email: string; password_hash: string | null; is_platform_admin: boolean }>(
      `SELECT id, email, password_hash, is_platform_admin FROM idp_users
        WHERE lower(email) LIKE '%@edams.local' OR lower(email) LIKE '%@gms.local' OR lower(email) = ANY($1::text[])
           OR lower(email) = ANY($2::text[])`,
      [named, BOOTSTRAP_ADMINS.map((b) => b.email)],
    );

    const targets: typeof candidates = [];
    const kept: string[] = [];
    for (const u of candidates) {
      const email = u.email.toLowerCase();
      const boot = BOOTSTRAP_ADMINS.find((b) => b.email === email);
      const explicit = named.includes(email);
      const isDemoDomain = email.endsWith('@edams.local') || email.endsWith('@gms.local');
      if (boot && !explicit && !isDemoDomain) {
        let stillDefault = false;
        for (const pw of boot.publicPasswords) if (await verifyPassword(pw, u.password_hash)) stillDefault = true;
        if (!stillDefault) { kept.push(`${u.email} (password has been changed: a real account, left alone)`); continue; }
      }
      targets.push(u);
    }

    if (targets.some((t) => t.is_platform_admin)) {
      console.error('\n  REFUSING: the target set contains a platform administrator. Nothing was changed.\n');
      await c.query('ROLLBACK');
      process.exit(3);
    }

    console.log(`  accounts to remove: ${targets.length}  (${targets.slice(0, 6).map((t) => t.email).join(', ')}${targets.length > 6 ? ', …' : ''})`);
    for (const k of kept) console.log(`  kept:               ${k}`);
    if (targets.length === 0) {
      console.log('\n  Nothing to remove.\n');
      await c.query('ROLLBACK');
      return;
    }

    const ids = targets.map((t) => t.id);
    const emails = targets.map((t) => t.email.toLowerCase());

    // Never leave the console with nobody who can open it.
    const { rows: remainingAdmins } = await c.query<{ n: string }>(
      `SELECT count(*)::text n FROM idp_user_groups g JOIN idp_users u ON u.id = g.user_id
        WHERE g.group_dn = $1 AND u.id <> ALL($2::uuid[]) AND u.is_active`,
      [IDP_CONFIG.adminGroup, ids],
    );
    if (Number(remainingAdmins[0].n) === 0) {
      console.error('\n  REFUSING: this would leave the admin console with no active administrator. Add or keep one first. Nothing was changed.\n');
      await c.query('ROLLBACK');
      process.exit(3);
    }

    const personalDns = ids.map((id) => `CN=user:${id},OU=Users,DC=examplecorp,DC=com`);
    const counts: Record<string, number> = {};
    const run = async (label: string, sql: string, params: unknown[]) => {
      const r = await c.query(sql, params);
      counts[label] = r.rowCount ?? 0;
    };
    await run('sessions and tokens (oidc_artifacts)', `DELETE FROM oidc_artifacts WHERE payload->>'accountId' = ANY($1::text[])`, [ids]);
    await run('portal / gateway / pending sessions', `DELETE FROM idp_web_sessions WHERE payload->>'accountId' = ANY($1::text[]) OR lower(coalesce(payload->>'email', '')) = ANY($2::text[])`, [ids, emails]);
    await run('sign-in history (idp_login_events)', `DELETE FROM idp_login_events WHERE lower(email) = ANY($1::text[])`, [emails]);
    await run('per-user role grants (idp_client_user_roles)', `DELETE FROM idp_client_user_roles WHERE lower(email) = ANY($1::text[])`, [emails]);
    await run('office pins (idp_gms_user_office)', `DELETE FROM idp_gms_user_office WHERE lower(email) = ANY($1::text[])`, [emails]);
    await run('personal-group entitlements', `DELETE FROM idp_app_entitlements WHERE group_dn = ANY($1::text[])`, [personalDns]);
    await run('personal-group GMS roles', `DELETE FROM idp_gms_role_mappings WHERE group_dn = ANY($1::text[])`, [personalDns]);
    await run('group memberships (idp_user_groups)', `DELETE FROM idp_user_groups WHERE user_id = ANY($1::uuid[])`, [ids]);
    await run('accounts (idp_users)', `DELETE FROM idp_users WHERE id = ANY($1::uuid[])`, [ids]);

    console.log('\n  rows that would be removed:');
    for (const [k, v] of Object.entries(counts)) if (v > 0) console.log(`    ${k.padEnd(52)} ${v}`);

    if (!EXECUTE) {
      await c.query('ROLLBACK');
      console.log('\n  Dry run only. Re-run with --execute to apply.\n');
      return;
    }
    await c.query('COMMIT');
    console.log(`\n  Removed ${targets.length} accounts and their access in one transaction. The admin audit trail was not touched.`);
    const logDir = path.resolve(process.cwd(), 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    const listFile = path.join(logDir, `cleanup-removed-personal-groups-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
    fs.writeFileSync(listFile, JSON.stringify({ database: dbName, removedAt: new Date().toISOString(), personalGroupDns: personalDns }, null, 2));
    console.log(`  Personal groups written to ${listFile}`);
    console.log('  Pass it to DMS/backend/scripts/cleanup-seed-data.ts as --personal-groups-file=<that path>.');

    // DMS holds the DMS role mapping for each personal group. Best effort: a DMS that is down
    // leaves harmless orphan mapping rows, and DMS's own cleanup-seed-data.ts removes them too.
    if (IDP_CONFIG.dmsInternalApiKey) {
      let cleared = 0;
      let failed = 0;
      for (const dn of personalDns) {
        try { await putDmsRoleMapping(IDP_CONFIG.dmsDefaultTenant, dn, [], 'cleanup-seed-data'); cleared++; } catch { failed++; }
      }
      console.log(`  DMS role mappings cleared: ${cleared}${failed ? ` (${failed} could not be reached; run DMS/backend/scripts/cleanup-seed-data.ts too)` : ''}`);
    }
    console.log('');
  } catch (err) {
    await c.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    await c.end();
  }
}

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
