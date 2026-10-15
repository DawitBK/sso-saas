/**
 * The platform owner's tool for the SSO platform-admin vault (migration
 * 015_platform_admin_protection.sql). Run it yourself, at a terminal.
 *
 *   npx tsx scripts/platform-vault.ts status
 *   npx tsx scripts/platform-vault.ts set              choose or change the vault password
 *   npx tsx scripts/platform-vault.ts mark <email>     make an EXISTING account the platform administrator
 *   npx tsx scripts/platform-vault.ts unmark <email>   undo that
 *   npx tsx scripts/platform-vault.ts sql "<SQL>"      run one statement with the vault open
 *   npx tsx scripts/platform-vault.ts reset-lockout    clear the failed-attempt lockout
 *   npx tsx scripts/platform-vault.ts forget           lost the password: clear it, then `set` again
 *
 * Mirror / production: prefix with the launcher so the right env file is read:
 *   node scripts/run-with-env.cjs production npx tsx scripts/platform-vault.ts status
 *
 * THE PASSWORD IS NEVER AN ARGUMENT, AN ENVIRONMENT VARIABLE, A FILE OR PIPED
 * INPUT. It is read from the terminal with echo off, sent to the database once,
 * and only a bcrypt hash is stored. This tool refuses to run without a real
 * terminal, so nothing automated (a script, CI, an AI agent) can drive it.
 * Nobody but the person at the keyboard can supply it, including whoever wrote
 * this tool.
 *
 * Marking an account tells SSO to treat it as the platform administrator: it then
 * disappears from every console list, cannot be disabled or locked out, and its
 * sign-ins are no longer recorded. Do this for the owner's account once the vault
 * password is set. (For a brand-new account use scripts/seed-platform-admin.ts.)
 */
import '../src/config.js';
import pg from 'pg';
import { IDP_CONFIG } from '../src/config.js';

function requireTerminal(): void {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.error('\n  This tool needs an interactive terminal. The vault password is never accepted from a pipe, a file or an argument.\n');
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
        if (c === '\u0003') {
          stdin.setRawMode(false);
          process.stdout.write('\n');
          process.exit(130);
        }
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
    process.stdin.once('data', (d) => {
      process.stdin.pause();
      resolve(String(d).trim());
    });
  });
}

async function connect(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: IDP_CONFIG.databaseUrl });
  await client.connect();
  return client;
}

async function openVault(c: pg.Client, minutes = 5): Promise<void> {
  const pw = await askHidden('  Vault password: ');
  const ok = (await c.query('SELECT platform_vault_unlock($1, $2) AS ok', [pw, minutes])).rows[0].ok;
  if (!ok) {
    console.error('\n  Wrong password (counted). Nothing was changed.\n');
    process.exit(1);
  }
}

async function status(c: pg.Client) {
  const set = await c.query('SELECT set_at FROM platform_vault WHERE id = 1');
  const fails = await c.query('SELECT platform_vault_failure_count()::int AS n');
  const open = await c.query('SELECT count(*)::int AS n FROM platform_vault_unlocked WHERE expires_at > now()');
  const flagged = await c.query('SELECT count(*)::int AS n FROM idp_users WHERE is_platform_admin');
  const log = await c.query('SELECT at, event, db_user FROM platform_vault_log ORDER BY id DESC LIMIT 10');
  console.log('\n  database:             ' + new URL(IDP_CONFIG.databaseUrl).pathname.slice(1));
  console.log(`  password set:         ${set.rowCount ? `yes (${new Date(set.rows[0].set_at).toISOString()})` : 'NO: run `set`'}`);
  console.log(`  failed attempts:      ${fails.rows[0].n} of 10 before lockout${fails.rows[0].n >= 10 ? '  *** LOCKED ***' : ''}`);
  console.log(`  open sessions:        ${open.rows[0].n}`);
  console.log(`  platform admin(s):    ${flagged.rows[0].n}`);
  console.log('  recent events:');
  for (const r of log.rows) console.log(`    ${new Date(r.at).toISOString()}  ${r.event}  (${r.db_user})`);
  console.log('');
}

async function setPassword(c: pg.Client) {
  const exists = (await c.query('SELECT 1 FROM platform_vault WHERE id = 1')).rowCount;
  if (exists) {
    const old = await askHidden('  Current vault password: ');
    const ok = (await c.query('SELECT platform_vault_unlock($1) AS ok', [old])).rows[0].ok;
    if (!ok) {
      console.error('\n  That is not the current vault password. Nothing was changed.\n');
      process.exit(1);
    }
  }
  const a = await askHidden('  New vault password (16+ characters; a passphrase is best): ');
  if (a.length < 16) {
    console.error('\n  Too short. Use at least 16 characters. Nothing was changed.\n');
    process.exit(1);
  }
  const b = await askHidden('  Type it again: ');
  if (a !== b) {
    console.error('\n  The two entries differ. Nothing was changed.\n');
    process.exit(1);
  }
  await c.query(
    `INSERT INTO platform_vault (id, secret_hash, set_at) VALUES (1, crypt($1, gen_salt('bf', 12)), now())
     ON CONFLICT (id) DO UPDATE SET secret_hash = EXCLUDED.secret_hash, set_at = now()`,
    [a],
  );
  await c.query(`INSERT INTO platform_vault_log (event) VALUES ('set')`);
  await c.query(`SELECT setval('platform_vault_failures', 1, false)`);
  console.log('\n  Vault password saved (only its hash is stored). Keep it where only you can reach it: it cannot be recovered.\n');
}

async function mark(c: pg.Client, email: string, value: boolean) {
  if (!email) {
    console.error(`\n  Usage: platform-vault.ts ${value ? 'mark' : 'unmark'} <email>\n`);
    process.exit(2);
  }
  await openVault(c);
  try {
    const res = await c.query(
      'UPDATE idp_users SET is_platform_admin = $2, updated_at = NOW() WHERE lower(email) = lower($1) RETURNING id',
      [email.trim(), value],
    );
    if (res.rowCount === 0) {
      console.error('\n  No account with that email exists in this database. Nothing was changed.\n');
      process.exit(1);
    }
    console.log(`\n  ${value ? 'Marked' : 'Unmarked'}: that account is ${value ? 'now' : 'no longer'} the platform administrator (id ${res.rows[0].id}).`);
    console.log('  Running servers pick this up within about 15 seconds.\n');
  } finally {
    await c.query('SELECT platform_vault_lock()');
  }
}

async function runSql(c: pg.Client, sql: string) {
  if (!sql) {
    console.error('\n  Usage: platform-vault.ts sql "<one SQL statement>"\n');
    process.exit(2);
  }
  await openVault(c);
  try {
    const res = await c.query(sql);
    if (res.rows?.length) console.table(res.rows);
    else console.log(`\n  OK${res.rowCount != null ? ` (${res.rowCount} rows)` : ''}\n`);
  } finally {
    await c.query('SELECT platform_vault_lock()');
  }
}

async function resetLockout(c: pg.Client) {
  const confirm = await askVisible('  Type RESET to clear the failed-attempt counter: ');
  if (confirm !== 'RESET') { console.log('  Cancelled.'); return; }
  await c.query(`SELECT setval('platform_vault_failures', 1, false)`);
  await c.query(`INSERT INTO platform_vault_log (event) VALUES ('reset')`);
  console.log('\n  Lockout cleared. The password itself is unchanged.\n');
}

async function forget(c: pg.Client) {
  console.log('\n  This deletes the stored password hash. Until you run `set` again NO ONE can open the vault,');
  console.log('  and the protected account stays protected (it simply cannot be changed). Only do this if the password is lost.');
  const confirm = await askVisible('  Type FORGET to continue: ');
  if (confirm !== 'FORGET') { console.log('  Cancelled.'); return; }
  await c.query('DELETE FROM platform_vault WHERE id = 1');
  await c.query(`SELECT setval('platform_vault_failures', 1, false)`);
  await c.query(`INSERT INTO platform_vault_log (event) VALUES ('reset')`);
  console.log('\n  Cleared. Run `set` now.\n');
}

async function main() {
  const cmd = process.argv[2];
  const known = ['status', 'set', 'mark', 'unmark', 'sql', 'reset-lockout', 'forget'];
  if (!cmd || !known.includes(cmd)) {
    console.log(`Usage: platform-vault.ts <${known.join(' | ')}>`);
    process.exit(2);
  }
  requireTerminal();
  const c = await connect();
  try {
    if (cmd === 'status') await status(c);
    else if (cmd === 'set') await setPassword(c);
    else if (cmd === 'mark') await mark(c, process.argv[3] ?? '', true);
    else if (cmd === 'unmark') await mark(c, process.argv[3] ?? '', false);
    else if (cmd === 'sql') await runSql(c, process.argv.slice(3).join(' ').trim());
    else if (cmd === 'reset-lockout') await resetLockout(c);
    else if (cmd === 'forget') await forget(c);
  } finally {
    await c.end();
  }
}

main().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
