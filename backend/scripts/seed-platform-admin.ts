/**
 * Creates the platform owner's SSO account: the one platform administrator.
 *
 * Run it yourself, at a terminal (it refuses without one). It asks, with echo
 * off, for two passwords that only you know and that are never written anywhere:
 *   1. the VAULT password (scripts/platform-vault.ts `set` chooses it), which the
 *      database requires before it will create or change a platform administrator;
 *   2. the new account's own sign-in password.
 *
 * What it creates, all on ONE vault-unlocked database connection, in one transaction:
 *  - the account, flagged is_platform_admin (invisible and untouchable: see
 *    auth/platform-admin.ts);
 *  - membership of IDP_CONFIG.adminGroup (the console gate) and of its own personal
 *    group;
 *  - entitlement to DMS and GMS, and GMS's org-wide super_admin role.
 * DMS's own PLATFORM_ADMIN role is NOT written from here any more: SSO can no
 * longer grant it (no console and no internal API can). It is granted by the DMS
 * side's own vault-protected script, DMS/backend/scripts/seed-platform-admin.ts,
 * which you run next with the same email and pepper.
 *
 * Identity at rest. With PLATFORM_ADMIN_PEPPER set (in the env file this backend
 * runs with; generate a long random value once and never change it), the account
 * is stored under a keyed pseudonym of your email, not the email itself, and you
 * still sign in by typing your real email. Then even a full read of the database
 * does not say who the platform administrator is. Without a pepper the real email
 * is stored (works, but the database then names you).
 *
 * The email comes from PLATFORM_ADMIN_EMAIL (not a secret) or is asked for.
 *
 * Usage (from SSO/backend). Mirror / production MUST go through run-with-env.cjs or
 * this silently targets the DEV database:
 *   Dev:    npx tsx scripts/seed-platform-admin.ts
 *   Mirror: node scripts/run-with-env.cjs mirror npx tsx scripts/seed-platform-admin.ts
 *   Prod:   node scripts/run-with-env.cjs production npx tsx scripts/seed-platform-admin.ts
 */
import pg from 'pg';
import { IDP_CONFIG } from '../src/config.js';
import { hashPassword } from '../src/auth/password.js';
import { platformAdminPseudonym } from '../src/auth/platform-admin.js';
import { personalGroupDn } from '../src/admin/access.js';

function requireTerminal(): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error('\n  This script needs an interactive terminal: the vault and account passwords are never accepted from a pipe, a file, an argument or an environment variable.\n');
    process.exit(2);
  }
}

function askHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (ch: string) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n' || c === '\u0004') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stdout.write('\n');
          resolve(buf);
          return;
        }
        if (c === '\u0003') { stdin.setRawMode(false); process.stdout.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1);
        else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

function askVisible(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    process.stdin.setEncoding('utf8');
    process.stdin.resume();
    process.stdin.once('data', (d) => { process.stdin.pause(); resolve(String(d).trim()); });
  });
}

async function main(): Promise<void> {
  requireTerminal();

  const realEmail = (process.env.PLATFORM_ADMIN_EMAIL?.trim() || (await askVisible('  Platform administrator email: '))).toLowerCase();
  if (!realEmail.includes('@')) {
    console.error('\n  That is not an email address.\n');
    process.exit(1);
  }
  const pepper = IDP_CONFIG.platformAdminPepper;
  const storedEmail = pepper ? platformAdminPseudonym(realEmail, pepper) : realEmail;
  console.log(pepper
    ? '\n  A pepper is configured: the database will store a keyed pseudonym, not your email.'
    : '\n  No PLATFORM_ADMIN_PEPPER configured: the database will store your real email. Set one first if you want it hidden at rest.');

  const accountPw = await askHidden('  Account sign-in password (12+ characters): ');
  if (accountPw.length < 12) {
    console.error('\n  Too short for this account. Nothing was changed.\n');
    process.exit(1);
  }
  if (accountPw !== (await askHidden('  Type it again: '))) {
    console.error('\n  The two entries differ. Nothing was changed.\n');
    process.exit(1);
  }
  const vaultPw = await askHidden('  Vault password: ');

  const passwordHash = await hashPassword(accountPw);
  const client = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await client.connect();
  try {
    const ok = (await client.query('SELECT platform_vault_unlock($1, 5) AS ok', [vaultPw])).rows[0].ok;
    if (!ok) {
      console.error('\n  Wrong vault password (counted). Nothing was changed.\n');
      process.exit(1);
    }
    await client.query('BEGIN');
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, must_change_password, is_platform_admin)
       VALUES ($1, TRUE, 'Platform', 'Administrator', $2, 'local', TRUE, FALSE, TRUE)
       ON CONFLICT (email) DO UPDATE SET
         password_hash = EXCLUDED.password_hash,
         is_active = TRUE,
         must_change_password = FALSE,
         is_platform_admin = TRUE,
         updated_at = NOW()
       RETURNING id`,
      [storedEmail, passwordHash],
    );
    const userId = rows[0].id;
    const personal = personalGroupDn(userId);

    for (const dn of [personal, IDP_CONFIG.adminGroup]) {
      await client.query('INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, dn]);
    }
    for (const rp of ['edams', 'gms']) {
      await client.query('INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [rp, personal]);
    }
    await client.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [personal]);
    await client.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2)', [personal, 'super_admin']);
    await client.query('COMMIT');
    console.log('\n  Done. The platform administrator account exists in this SSO database.');
    console.log(`  Stored as: ${pepper ? 'a keyed pseudonym (you sign in with your real email)' : 'your real email'}.`);
    console.log('  Next: run DMS/backend/scripts/seed-platform-admin.ts with the same email and pepper to give it its DMS role.\n');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    await client.query('SELECT platform_vault_lock()').catch(() => {});
    await client.end();
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
