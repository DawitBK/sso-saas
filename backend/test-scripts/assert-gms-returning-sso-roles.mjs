/**
 * Live-verify GMS internal SSO session minting prefers SSO-supplied roles for
 * returning staff (directive §6.3), without rewriting local role tables.
 */
import { decodeJwt } from 'jose';
import pg from 'pg';

const GMS = 'http://localhost:7200/api/v1';
const EMAIL = 'admin@examplecorp.com';
const SSO_ROLE = 'super_admin';
const STALE_LOCAL_ROLE = 'guest';

async function main() {
  const apiKey = process.env.SSO_INTERNAL_API_KEY
    ?? process.env.GMS_INTERNAL_API_KEY;
  if (!apiKey) {
    throw new Error('Set SSO_INTERNAL_API_KEY or GMS_INTERNAL_API_KEY in env');
  }

  const client = new pg.Client({
    host: 'localhost',
    port: 5432,
    user: 'postgres',
    password: 'leadfreak',
    database: 'gmsdev',
  });
  await client.connect();

  const { rows: users } = await client.query(
    `SELECT u.id FROM users u WHERE lower(u.email) = lower($1) LIMIT 1`,
    [EMAIL],
  );
  if (!users.length) throw new Error(`GMS user ${EMAIL} not found — run bridge login first`);

  const userId = users[0].id;
  const { rows: roleRows } = await client.query(
    `SELECT id, name FROM roles WHERE name = ANY($1::text[])`,
    [[STALE_LOCAL_ROLE, SSO_ROLE]],
  );
  const byName = Object.fromEntries(roleRows.map((r) => [r.name, r.id]));
  if (!byName[STALE_LOCAL_ROLE] || !byName[SSO_ROLE]) {
    throw new Error('required GMS roles missing');
  }

  await client.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);
  await client.query(
    `INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [userId, byName[STALE_LOCAL_ROLE]],
  );
  console.log(`seeded local user_roles = [${STALE_LOCAL_ROLE}]`);

  const before = await client.query(
    `SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name`,
    [userId],
  );
  console.log('local roles before SSO session:', before.rows.map((r) => r.name));

  const resp = await fetch(`${GMS}/internal/sso/sessions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-internal-api-key': apiKey,
    },
    body: JSON.stringify({
      email: EMAIL,
      givenName: 'Admin',
      familyName: 'User',
      initialRoles: [SSO_ROLE],
    }),
  });
  const body = await resp.json();
  if (resp.status !== 200 || !body.success) {
    throw new Error('session mint failed: ' + JSON.stringify(body));
  }

  const accessToken = body.data?.accessToken;
  if (!accessToken) throw new Error('no accessToken');

  const decoded = decodeJwt(accessToken);
  const tokenRoles = decoded?.roles ?? [];
  console.log('session JWT roles:', JSON.stringify(tokenRoles));

  const after = await client.query(
    `SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name`,
    [userId],
  );
  console.log('local roles after SSO session:', after.rows.map((r) => r.name));

  const ok = tokenRoles.includes(SSO_ROLE)
    && !tokenRoles.includes(STALE_LOCAL_ROLE)
    && after.rows.some((r) => r.name === STALE_LOCAL_ROLE);

  await client.end();
  console.log('\nRESULT:', ok ? 'PASS' : 'FAIL');
  if (!ok) process.exit(1);
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });
