/**
 * Live verification of the SSO half of "the platform administrator is invisible
 * and untouchable". Run (needs the local Postgres superuser):
 *   npx tsx test-scripts/verify-platform-admin.ts
 *
 * It builds a SCRATCH database (idp_pa_scratch) from the real migrations, so it
 * never touches real data, and drops it afterwards. The vault password it uses is
 * generated in memory for this run only and is unrelated to the real vault.
 *
 * Then it drives the REAL admin routers over HTTP, signed in as an ordinary IdP
 * administrator, and tries to find, read, change, sign out and remove the platform
 * administrator; checks the sign-in / session / audit views; checks the sign-in
 * path (real email maps to the stored pseudonym, nothing is recorded); the
 * "downgraded IdP admin" rule for signing keys and the admin group; and finally
 * attacks the account directly in SQL with the vault closed.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import pg from 'pg';

const SUPER_URL = process.env.VERIFY_SUPERUSER_URL || process.env.DATABASE_URL || 'postgres://postgres:change-me-dev-password@localhost:5432/postgres';
const SCRATCH = 'idp_pa_scratch';
const base = new URL(SUPER_URL);
const scratchUrl = (() => { const u = new URL(SUPER_URL); u.pathname = `/${SCRATCH}`; return u.toString(); })();

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean, extra = '') {
  if (ok) { passed++; console.log(`  ok   ${name}`); } else { failed++; console.log(`  FAIL ${name} ${extra}`); }
}

async function admin(sql: string) {
  const c = new pg.Client({ connectionString: (() => { const u = new URL(SUPER_URL); u.pathname = '/postgres'; return u.toString(); })() });
  await c.connect();
  try { await c.query(sql); } finally { await c.end(); }
}

async function main() {
  await admin(`DROP DATABASE IF EXISTS ${SCRATCH} WITH (FORCE)`);
  await admin(`CREATE DATABASE ${SCRATCH}`);

  // Point the app at the scratch database BEFORE any app module loads (config reads env at import).
  // config.ts re-reads `.env` from the CURRENT DIRECTORY with override:true, which would silently swap
  // the scratch URL back to the real dev database. Run from an empty directory so there is no env file.
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sso-pa-verify-'));
  process.chdir(emptyDir);
  process.env.DATABASE_URL = scratchUrl;
  process.env.DATABASE_URL_TRUSTED = '1';
  process.env.PLATFORM_ADMIN_PEPPER = 'scratch-pepper-' + crypto.randomBytes(8).toString('hex');
  process.env.NODE_ENV = 'development';

  const { runMigrations } = await import('../src/db/migrate.js');
  const { pool } = await import('../src/db/pool.js');
  const { IDP_CONFIG } = await import('../src/config.js');
  const { putPortalSession } = await import('../src/portal/session.js');
  const { adminApiRouter } = await import('../src/api/v1/admin.router.js');
  const { adminMutationsRouter } = await import('../src/api/v1/admin-mutations.router.js');
  const { authenticateUser } = await import('../src/auth/account.js');
  const { hashPassword } = await import('../src/auth/password.js');
  const { platformAdminPseudonym, invalidatePlatformAdminCache } = await import('../src/auth/platform-admin.js');
  const { writeAudit } = await import('../src/admin/audit.js');
  const express = (await import('express')).default;

  if (!IDP_CONFIG.databaseUrl.includes(SCRATCH)) {
    throw new Error(`Refusing to run: the app resolved its database to ${IDP_CONFIG.databaseUrl.replace(/:[^:@/]+@/, ':***@')}, not the scratch database.`);
  }
  await runMigrations();

  // ---- seed: a vault only this run knows, the platform admin, an IdP admin, a normal user
  const vaultPw = 'scratch-vault-' + crypto.randomBytes(12).toString('hex');
  const realPaEmail = 'owner.real@example.com';
  const paStored = platformAdminPseudonym(realPaEmail, IDP_CONFIG.platformAdminPepper);
  const paPassword = 'Correct-Horse-Battery-9';
  const seed = new pg.Client({ connectionString: scratchUrl });
  await seed.connect();
  await seed.query(`INSERT INTO platform_vault (id, secret_hash) VALUES (1, crypt($1, gen_salt('bf', 6)))`, [vaultPw]);
  check('vault accepts the right password', (await seed.query('SELECT platform_vault_unlock($1) AS ok', [vaultPw])).rows[0].ok === true);
  const paHash = await hashPassword(paPassword);
  const pa = (await seed.query(
    `INSERT INTO idp_users (email,email_verified,given_name,family_name,password_hash,source,is_active,is_platform_admin) VALUES ($1,true,'Platform','Administrator',$2,'local',true,true) RETURNING id`,
    [paStored, paHash])).rows[0].id as string;
  await seed.query(`INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1,$2)`, [pa, IDP_CONFIG.adminGroup]);
  await seed.query('SELECT platform_vault_lock()');
  const idpAdmin = (await seed.query(
    `INSERT INTO idp_users (email,email_verified,given_name,family_name,password_hash,source,is_active) VALUES ('idp.admin@example.com',true,'Ida','Admin',$1,'local',true) RETURNING id`, [paHash])).rows[0].id as string;
  const victim = (await seed.query(
    `INSERT INTO idp_users (email,email_verified,given_name,family_name,password_hash,source,is_active) VALUES ('victim@example.com',true,'Vic','Tim',$1,'local',true) RETURNING id`, [paHash])).rows[0].id as string;
  await seed.query(`INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1,$2)`, [idpAdmin, IDP_CONFIG.adminGroup]);
  invalidatePlatformAdminCache();

  // sessions, sign-in events and audit rows for everyone
  const now = Date.now();
  for (const [acc, jti] of [[pa, 'sess-pa'], [victim, 'sess-victim'], [null, 'sess-anon']] as const) {
    await seed.query(
      `INSERT INTO oidc_artifacts (id, kind, payload, expires_at) VALUES ($1,'Session',$2,$3)`,
      [jti, JSON.stringify(acc ? { jti, accountId: acc } : { jti }), new Date(now + 3600_000)]);
  }
  await seed.query(`INSERT INTO idp_login_events (email, success, reason, ip, user_agent) VALUES ($1,true,'','203.0.113.7','Mozilla'),($2,true,'','198.51.100.9','Mozilla'),($2,false,'invalid_credentials','198.51.100.9','Mozilla')`, [paStored, 'victim@example.com']);
  const fakeReq: any = { ip: '127.0.0.1', get: () => 'test' };
  await writeAudit(fakeReq, paStored, 'signing_key.generate', 'system', { kid: 'k-pa' });
  await writeAudit(fakeReq, 'idp.admin@example.com', 'user.update', 'victim@example.com', { userId: victim });
  const rawAudit = (await seed.query(`SELECT actor_email, ip, user_agent FROM idp_admin_audit ORDER BY sequence_number`)).rows;
  check('platform admin audit row is anonymous (actor, address, browser all blank)', rawAudit[0].actor_email === 'platform' && rawAudit[0].ip === '' && rawAudit[0].user_agent === '');
  check('an ordinary admin audit row is untouched', rawAudit[1].actor_email === 'idp.admin@example.com' && rawAudit[1].ip === '127.0.0.1');

  // ---- sign-in path
  console.log('\nsigning in');
  const viaReal = await authenticateUser(realPaEmail, paPassword, '203.0.113.7');
  check('real email + password signs the platform admin in (pseudonym looked up)', viaReal.ok === true && (viaReal as any).accountId === pa);
  check('the sign-in is flagged so nothing is recorded', (viaReal as any).platformAdmin === true);
  const viaWrong = await authenticateUser(realPaEmail, 'wrong-password-123', '203.0.113.7');
  check('wrong password is refused and flagged', viaWrong.ok === false && (viaWrong as any).platformAdmin === true);
  for (let i = 0; i < 12; i++) await authenticateUser(realPaEmail, 'guess-' + i, '203.0.113.7');
  const stillIn = await authenticateUser(realPaEmail, paPassword, '203.0.113.7');
  check('twelve wrong guesses cannot lock the platform admin out', stillIn.ok === true);
  const lockCols = (await seed.query('SELECT failed_logins, locked_until FROM idp_users WHERE id=$1', [pa])).rows[0];
  check('and the database kept the lock columns clear', lockCols.failed_logins === 0 && lockCols.locked_until === null);

  // ---- HTTP: real routers, signed in as an ordinary IdP admin
  const app = express();
  // main.ts parses JSON bodies once at the /api/v1 mount; the admin router relies on that.
  app.use('/api/v1', express.json({ limit: '1mb' }));
  app.use('/api/v1/admin', adminApiRouter());
  app.use('/api/v1/admin', adminMutationsRouter({} as any));
  app.use((err: any, _req: any, res: any, _next: any) => { res.status(500).json({ error: String(err?.message ?? err) }); });
  const server = http.createServer(app);
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  const ckAdmin = await putPortalSession({ accountId: idpAdmin, name: 'Ida Admin', email: 'idp.admin@example.com', groups: [IDP_CONFIG.adminGroup] });
  const ckPa = await putPortalSession({ accountId: pa, name: 'Platform', email: paStored, groups: [IDP_CONFIG.adminGroup] });
  const CSRF = 'csrf-' + crypto.randomBytes(6).toString('hex');
  const call = async (method: string, path: string, session: string, body?: unknown) => {
    const r = await fetch(`http://127.0.0.1:${port}/api/v1/admin${path}`, {
      method,
      headers: { cookie: `idp_portal=${session}; idp_admin_api_csrf=${CSRF}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify({ csrf: CSRF, ...(body as object) }),
    });
    const text = await r.text();
    let data: any; try { data = JSON.parse(text); } catch { data = text; }
    return { status: r.status, data };
  };
  const dump = (x: unknown) => JSON.stringify(x);

  console.log('\nlists and views never contain the platform admin');
  const users = await call('GET', '/users', ckAdmin);
  check('GET /users answers 200', users.status === 200, `(${users.status} ${dump(users.data).slice(0, 120)})`);
  const emails = (users.data?.data?.users ?? []).map((u: any) => u.email);
  check('platform admin absent from the user list', !dump(users.data).includes(paStored) && !dump(users.data).includes(pa));
  check('ordinary users still listed', emails.includes('victim@example.com') && emails.includes('idp.admin@example.com'));
  check('user total excludes it', users.data?.data?.pagination?.total === 2);
  const stats = await call('GET', '/stats', ckAdmin);
  check('dashboard user count excludes it', stats.data?.data?.userCount === 2, `(${dump(stats.data).slice(0, 160)})`);
  const grp = await call('GET', `/groups/detail?dn=${encodeURIComponent(IDP_CONFIG.adminGroup)}`, ckAdmin);
  check('IdP admin group member list excludes it', !dump(grp.data).includes(paStored) && dump(grp.data).includes('idp.admin@example.com'));
  const sess = await call('GET', '/sessions', ckAdmin);
  check('active sessions exclude the platform admin', !dump(sess.data).includes(pa) && !dump(sess.data).includes(paStored));
  const sessRows = sess.data?.data?.sessions ?? [];
  check('active sessions list only real signed-in accounts (anonymous session dropped)', sessRows.length === 1 && sessRows[0].account_id === victim);
  check('active session shows the real email and the real account id from the database', sessRows[0]?.email === 'victim@example.com' && sessRows[0]?.account_id === victim);
  check('session count agrees with the list', sess.data?.data?.pagination?.total === 1);
  const logins = await call('GET', '/logins', ckAdmin);
  check('sign-in history excludes the platform admin', !dump(logins.data).includes(paStored) && !dump(logins.data).includes('203.0.113.7'));
  const lrows = logins.data?.data?.logins ?? [];
  check('sign-in rows for others carry the real account id and the real address', lrows.length === 2 && lrows.every((l: any) => l.account_id === victim && l.ip === '198.51.100.9'));
  const audit = await call('GET', '/audit', ckAdmin);
  check('audit view shows no platform-admin identity', !dump(audit.data).includes(paStored) && !dump(audit.data).includes(pa));
  const catalog = await call('GET', '/role-catalog', ckAdmin);
  check('role catalog does not offer PLATFORM_ADMIN', !dump(catalog.data).includes('PLATFORM_ADMIN'));

  console.log('\na request that names the platform admin reads as "user not found"');
  const missing = await call('GET', '/users/00000000-0000-0000-0000-00000000dead', ckAdmin);
  for (const [method, path, body] of [
    ['GET', `/users/${pa}`, undefined],
    ['PUT', `/users/${pa}`, { is_active: false }],
    ['POST', `/users/${pa}/toggle-active`, {}],
    ['POST', `/users/${pa}/reset-password`, { password: 'Whatever-123456' }],
    ['POST', `/users/${pa}/mfa-reset`, {}],
    ['POST', `/users/${pa}/access`, { dms_role: [], is_admin: false }],
    ['POST', `/users/${pa}/dms-permissions`, {}],
    ['POST', `/users/${pa}/groups`, { group_dn: 'CN=x' }],
    ['POST', `/users/${pa}/groups/remove`, { group_dn: IDP_CONFIG.adminGroup }],
  ] as [string, string, unknown][]) {
    const r = await call(method, path, ckAdmin, body);
    check(`${method} ${path.replace(pa, 'PA')} -> 404`, r.status === 404, `(got ${r.status} ${dump(r.data).slice(0, 100)})`);
  }
  const hidden = await call('GET', `/users/${pa}`, ckAdmin);
  check('hidden user and nonexistent user answer identically', hidden.status === missing.status && dump(hidden.data.error?.code) === dump(missing.data.error?.code));
  const selfView = await call('GET', `/users/${pa}`, ckPa);
  check('the platform admin can still open its own record', selfView.status === 200, `(${selfView.status})`);

  console.log('\nthe IdP administrator group is downgraded below the platform admin');
  const keyGen = await call('POST', '/keys/generate', ckAdmin, {});
  check('an IdP admin cannot generate a signing key', keyGen.status === 403 && keyGen.data?.error?.code === 'ERR-PLATFORM-ADMIN-ONLY', `(${keyGen.status} ${dump(keyGen.data).slice(0, 100)})`);
  const keyRetire = await call('POST', '/keys/some-kid/retire', ckAdmin, {});
  check('an IdP admin cannot retire or withdraw a signing key', keyRetire.status === 403 && keyRetire.data?.error?.code === 'ERR-PLATFORM-ADMIN-ONLY');
  const keysAsAdmin = await call('GET', '/keys', ckAdmin);
  check('an IdP admin cannot even list the signing keys', keysAsAdmin.status === 403 && keysAsAdmin.data?.error?.code === 'ERR-PLATFORM-ADMIN-ONLY', `(${keysAsAdmin.status})`);
  const keysAsPa = await call('GET', '/keys', ckPa);
  check('the platform admin can list the signing keys and manage them', keysAsPa.status === 200 && keysAsPa.data?.data?.canManage === true, `(${keysAsPa.status})`);
  const grantAdmin = await call('POST', `/users/${victim}/groups`, ckAdmin, { group_dn: IDP_CONFIG.adminGroup });
  check('an IdP admin cannot make someone an IdP admin', grantAdmin.status === 403 && grantAdmin.data?.error?.code === 'ERR-PLATFORM-ADMIN-ONLY', `(${grantAdmin.status} ${dump(grantAdmin.data).slice(0, 100)})`);
  const revokeAdmin = await call('POST', `/users/${idpAdmin}/groups/remove`, ckAdmin, { group_dn: IDP_CONFIG.adminGroup });
  check('nor remove another IdP admin', revokeAdmin.status === 403 && revokeAdmin.data?.error?.code === 'ERR-PLATFORM-ADMIN-ONLY');
  const viaAccess = await call('POST', `/users/${victim}/access`, ckAdmin, { is_admin: 'on', dms_role: [], gms_role: '' });
  check('nor through the access form checkbox', viaAccess.status === 403 && viaAccess.data?.error?.code === 'ERR-PLATFORM-ADMIN-ONLY', `(${viaAccess.status} ${dump(viaAccess.data).slice(0, 100)})`);
  const inAdminGroup = (await seed.query('SELECT count(*)::int n FROM idp_user_groups WHERE user_id=$1 AND group_dn=$2', [victim, IDP_CONFIG.adminGroup])).rows[0].n;
  check('and the victim did not become an IdP admin', inAdminGroup === 0);

  console.log('\nthe Users list filters (client, role, status, source)');
  const GMS_GROUP = 'CN=gms-hosts,OU=Groups,DC=example,DC=com';
  await seed.query(`INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1,$2)`, [victim, GMS_GROUP]);
  await seed.query(`INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ('gms',$1)`, [GMS_GROUP]);
  await seed.query(`INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1,'host')`, [GMS_GROUP]);
  const listed = async (qs: string) => {
    const r = await call('GET', `/users?${qs}`, ckAdmin);
    return { status: r.status, emails: ((r.data?.data?.users ?? []) as any[]).map((u) => u.email).sort(), total: r.data?.data?.pagination?.total, code: r.data?.error?.code };
  };
  check('no filter: both ordinary users', JSON.stringify((await listed('')).emails) === JSON.stringify(['idp.admin@example.com', 'victim@example.com']));
  check('client=gms (gated by an entitlement): only entitled users', JSON.stringify((await listed('client=gms')).emails) === JSON.stringify(['victim@example.com']));
  check('client=edams (no entitlement rows, open to everyone): everyone', (await listed('client=edams')).emails.length === 2);
  check('client=portal adds no filter', (await listed('client=portal')).emails.length === 2);
  check('client=bogus is ignored, not an error', (await listed('client=bogus')).status === 200);
  check('role=gms:host via a group mapping', JSON.stringify((await listed('role=gms:host')).emails) === JSON.stringify(['victim@example.com']));
  check('role=gms:admin matches nobody yet', (await listed('role=gms:admin')).emails.length === 0);
  await seed.query(`INSERT INTO idp_client_user_roles (email, client_id, role_name, granted_by) VALUES ('victim@example.com','gms','reception','test')`);
  check('a per-user GMS grant OVERRIDES the group mapping (no longer host)', (await listed('role=gms:host')).emails.length === 0);
  check('and the user now appears under the granted role', JSON.stringify((await listed('role=gms:reception')).emails) === JSON.stringify(['victim@example.com']));
  check('role=idp:admin finds the IdP administrator and never the platform admin', JSON.stringify((await listed('role=idp:admin')).emails) === JSON.stringify(['idp.admin@example.com']));
  const noDms = await listed('role=dms:EXECUTIVE');
  check('role=dms:* with DMS unreachable says so instead of returning a wrong list', noDms.status >= 500 && noDms.code === 'ERR-DMS-ROLE-FILTER', `(${noDms.status} ${noDms.code})`);
  await seed.query(`UPDATE idp_users SET is_active=false WHERE id=$1`, [victim]);
  check('status=inactive', JSON.stringify((await listed('status=inactive')).emails) === JSON.stringify(['victim@example.com']));
  check('status=active', JSON.stringify((await listed('status=active')).emails) === JSON.stringify(['idp.admin@example.com']));
  check('filters combine (client=gms AND status=active -> nobody)', (await listed('client=gms&status=active')).emails.length === 0);
  check('the total follows the filter', (await listed('status=inactive')).total === 1);
  check('a platform admin never appears under any filter', !(await Promise.all(['', 'status=active', 'role=idp:admin', 'client=gms', 'source=local'].map(listed))).some((r) => r.emails.some((e: string) => e.includes('platform.invalid'))));

  console.log('\ndatabase layer, vault closed');
  const attacks: [string, string][] = [
    ['delete the account', `DELETE FROM idp_users WHERE id='${pa}'`],
    ['disable it', `UPDATE idp_users SET is_active=false WHERE id='${pa}'`],
    ['rename it', `UPDATE idp_users SET email='x@y.z' WHERE id='${pa}'`],
    ['un-flag it', `UPDATE idp_users SET is_platform_admin=false WHERE id='${pa}'`],
    ['flag an ordinary user', `UPDATE idp_users SET is_platform_admin=true WHERE id='${victim}'`],
    ['create another platform admin', `INSERT INTO idp_users (email,email_verified,source,is_active,is_platform_admin) VALUES ('rogue@x.y',true,'local',true,true)`],
    ['remove it from its group', `DELETE FROM idp_user_groups WHERE user_id='${pa}'`],
    ['add it to a group', `INSERT INTO idp_user_groups (user_id, group_dn) VALUES ('${pa}','CN=extra')`],
  ];
  for (const [what, sql] of attacks) {
    let refused = false;
    try { await seed.query(sql); } catch (e) { refused = /platform administrator|vault/i.test((e as Error).message); }
    check(`cannot ${what}`, refused);
  }
  check('a failed unlock is counted even inside a rolled-back transaction', await (async () => {
    const before = Number((await seed.query('SELECT platform_vault_failure_count() n')).rows[0].n);
    await seed.query('BEGIN'); await seed.query(`SELECT platform_vault_unlock('guess')`); await seed.query('ROLLBACK');
    return Number((await seed.query('SELECT platform_vault_failure_count() n')).rows[0].n) === before + 1;
  })());
  const stillThere = (await seed.query('SELECT is_active, is_platform_admin, email FROM idp_users WHERE id=$1', [pa])).rows[0];
  check('the account is exactly as it was', stillThere.is_active && stillThere.is_platform_admin && stillThere.email === paStored);
  check('the real email is not anywhere in the table', (await seed.query(`SELECT count(*)::int n FROM idp_users WHERE email ILIKE '%owner.real%' OR given_name ILIKE '%owner%'`)).rows[0].n === 0);

  server.close();
  await seed.end();
  await pool.end();
  await admin(`DROP DATABASE IF EXISTS ${SCRATCH} WITH (FORCE)`);
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (e) => {
  console.error(e);
  try { await admin(`DROP DATABASE IF EXISTS ${SCRATCH} WITH (FORCE)`); } catch { /* ignore */ }
  process.exit(1);
});
