/**
 * Live-verify DMS OIDC callback prefers SSO edams role claims for returning
 * users (directive §6.3), not stale local user_roles rows.
 *
 * Setup: ensure admin@examplecorp.com exists in DMS with a deliberately wrong
 * local role (EMPLOYEE) while SSO still maps them to SYSTEM_ADMIN via claims.
 */
import { decodeJwt } from 'jose';
import pg from 'pg';

const DMS = 'http://localhost:7100/api/v1';
const IDP_PUBLIC = (process.env.IDP_ISSUER ?? 'http://localhost:7301').replace(/\/$/, '');
const IDP_INTERNAL = (process.env.IDP_INTERNAL_URL ?? 'http://localhost:7300').replace(/\/$/, '');
const REDIRECT_URI = 'http://localhost:7101/auth/callback';
const EMAIL = 'admin@examplecorp.com';
const EXPECTED_ROLE = 'SYSTEM_ADMIN';
const STALE_LOCAL_ROLE = 'EMPLOYEE';

const jar = new Map();
function store(resp) {
  for (const c of resp.headers.getSetCookie?.() ?? []) {
    const [pair] = c.split(';');
    const i = pair.indexOf('=');
    const n = pair.slice(0, i).trim();
    const v = pair.slice(i + 1).trim();
    if (v === '') jar.delete(n); else jar.set(n, v);
  }
}
const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const isRedirect = (s) => [301, 302, 303, 307, 308].includes(s);
async function get(url) {
  const r = await fetch(url, { headers: { cookie: cookie() }, redirect: 'manual' });
  store(r);
  return r;
}
async function postForm(url, form) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
    redirect: 'manual',
  });
  store(r);
  return r;
}
async function follow(r) {
  for (let i = 0; i < 10; i++) {
    if (!isRedirect(r.status)) return r;
    const loc = r.headers.get('location');
    if (loc.startsWith(REDIRECT_URI)) return r;
    r = await get(loc.startsWith('http') ? loc : IDP_PUBLIC + loc);
  }
  return r;
}
const field = (h, n) => (h.match(new RegExp(`name="${n}"[^>]*value="([^"]*)"`)) || [])[1];
const uidOf = (h) => (h.match(/\/interaction\/([^/"]+)\/(?:login|confirm)/) || [])[1];

async function seedStaleLocalRole(client) {
  const { rows: users } = await client.query(
    'SELECT id FROM users WHERE lower(email) = lower($1) LIMIT 1',
    [EMAIL],
  );
  if (!users.length) {
    console.log('   user not found — first login will provision; skipping stale-role seed');
    return false;
  }
  const userId = users[0].id;
  const { rows: roles } = await client.query(
    `SELECT r.id, r.name FROM roles r WHERE r.name = ANY($1::text[])`,
    [[STALE_LOCAL_ROLE, EXPECTED_ROLE]],
  );
  const byName = Object.fromEntries(roles.map((r) => [r.name, r.id]));
  if (!byName[STALE_LOCAL_ROLE]) throw new Error(`role ${STALE_LOCAL_ROLE} missing in DMS`);
  await client.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);
  await client.query(
    `INSERT INTO user_roles (id, user_id, role_id, assigned_at)
     VALUES (gen_random_uuid(), $1, $2, NOW()) ON CONFLICT DO NOTHING`,
    [userId, byName[STALE_LOCAL_ROLE]],
  );
  console.log(`   seeded local user_roles = [${STALE_LOCAL_ROLE}] for returning-user test`);
  return true;
}

async function oidcLogin() {
  let r = await get(`${DMS}/auth/oidc/authorize`);
  if (!isRedirect(r.status)) throw new Error('DMS authorize did not redirect');
  r = await follow(await get(r.headers.get('location')));

  if (r.status === 200) {
    let html = await r.text();
    let uid = uidOf(html);
    let csrf = field(html, 'csrf');
    if (uid && csrf) {
      r = await follow(await postForm(`${IDP_PUBLIC}/interaction/${uid}/login`, {
        csrf, email: EMAIL, password: 'demo',
      }));
    }
    if (r.status === 200) {
      html = await r.text();
      uid = uidOf(html);
      csrf = field(html, 'csrf');
      if (uid && csrf) {
        r = await follow(await postForm(`${IDP_PUBLIC}/interaction/${uid}/confirm`, { csrf }));
      }
    }
  }

  const loc = r.headers.get('location') || '';
  if (!loc.startsWith(REDIRECT_URI)) {
    throw new Error('expected redirect to callback, got: ' + loc.slice(0, 200));
  }
  const code = new URL(loc).searchParams.get('code');
  const state = new URL(loc).searchParams.get('state');
  if (!code || !state) throw new Error('no code/state');

  const cb = await fetch(`${DMS}/auth/callback`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, state }),
  });
  const data = await cb.json();
  if (cb.status !== 200) throw new Error('callback failed: ' + JSON.stringify(data));
  return data;
}

async function main() {
  const client = new pg.Client({
    host: 'localhost',
    port: 5432,
    user: 'postgres',
    password: 'leadfreak',
    database: 'DMS',
  });
  await client.connect();
  const hadUser = await seedStaleLocalRole(client);
  await client.end();

  const data = await oidcLogin();
  const tokenRoles = data.user?.roles ?? [];
  const jwtRoles = data.accessToken ? (decodeJwt(data.accessToken).roles ?? []) : [];

  console.log('callback roles:', JSON.stringify(tokenRoles));
  console.log('jwt roles:', JSON.stringify(jwtRoles));

  const claimsWin = tokenRoles.includes(EXPECTED_ROLE)
    && !tokenRoles.includes(STALE_LOCAL_ROLE)
    && jwtRoles.includes(EXPECTED_ROLE);

  // When user didn't exist, first provision should still get SYSTEM_ADMIN from claims
  const firstProvisionOk = !hadUser && tokenRoles.includes(EXPECTED_ROLE);
  const ok = claimsWin || firstProvisionOk;

  console.log('\nRESULT:', ok ? 'PASS' : 'FAIL');
  if (!ok) process.exit(1);
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });
