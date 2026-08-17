/**
 * Live end-to-end verification of the SSO-GAP-004 (GMS side) fix.
 *
 * Picks a real GMS staff user, changes their role via SSO's NEW per-user
 * grant API (simulating an admin acting through SSO rather than GMS
 * directly), confirms SSO now resolves the NEW role for them (not their
 * stale local one), then feeds that resolution into GMS's real internal
 * session-mint endpoint (the exact call bridge/gms.ts's mintGmsSession makes)
 * and confirms the resulting session JWT carries the NEW role — proving the
 * whole chain (SSO grant -> resolution -> GMS session mint -> issued token)
 * without requiring a full browser OIDC login.
 */
import { decodeJwt } from 'jose';
import pg from 'pg';

const SSO = 'http://localhost:7300';
const GMS = 'http://localhost:7200/api/v1';
const EMAIL = 'reception.ho6f@examplecorp.com';
const NEW_SSO_ROLE = 'super_reception';

async function main() {
  const ssoKey = process.env.SSO_ROLES_API_KEY;
  const gmsKey = process.env.SSO_INTERNAL_API_KEY ?? process.env.GMS_INTERNAL_API_KEY;
  if (!ssoKey) throw new Error('Set SSO_ROLES_API_KEY in env');
  if (!gmsKey) throw new Error('Set SSO_INTERNAL_API_KEY or GMS_INTERNAL_API_KEY in env');

  const client = new pg.Client({ host: 'localhost', port: 5432, user: 'postgres', password: 'leadfreak', database: 'gmsdev' });
  await client.connect();
  const { rows: before } = await client.query(
    `SELECT r.name FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id WHERE lower(u.email) = lower($1) ORDER BY r.name`,
    [EMAIL],
  );
  const localRolesBefore = before.map((r) => r.name);
  console.log(`GMS local roles for ${EMAIL} (untouched by this test):`, localRolesBefore);
  if (!localRolesBefore.length || localRolesBefore.includes(NEW_SSO_ROLE)) {
    throw new Error(`Test needs a user whose local role differs from ${NEW_SSO_ROLE} — pick another EMAIL`);
  }

  // 1. Admin action, but through SSO's new API (not GMS) — this is the §6.3
  //    "GMS's admin UI writes through SSO" workflow, exercised from the SSO
  //    side directly to isolate this step from GMS's own admin endpoint.
  const putResp = await fetch(`${SSO}/internal/gms/users/${encodeURIComponent(EMAIL)}/roles`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', 'x-internal-api-key': ssoKey },
    body: JSON.stringify({ roles: [NEW_SSO_ROLE], grantedBy: 'live-test' }),
  });
  const putBody = await putResp.json();
  if (putResp.status !== 200 || !putBody.success) throw new Error('SSO grant write failed: ' + JSON.stringify(putBody));
  console.log('SSO grant set to:', putBody.data.roles);

  // 2. Confirm SSO resolves the NEW role (this is what bridge/gms.ts's
  //    resolveGmsRoles would return for this email with no AD group match).
  const getResp = await fetch(`${SSO}/internal/gms/users/${encodeURIComponent(EMAIL)}/roles`, {
    headers: { 'x-internal-api-key': ssoKey },
  });
  const getBody = await getResp.json();
  const resolvedRoles = getBody.data.roles;
  console.log('SSO resolves roles as:', resolvedRoles);
  if (!resolvedRoles.includes(NEW_SSO_ROLE)) throw new Error('SSO did not resolve the new role');

  // 3. Feed that resolution into GMS's real internal session-mint endpoint —
  //    the exact call the bridge makes — and confirm the minted token
  //    reflects the NEW role, not the stale local one.
  const sessionResp = await fetch(`${GMS}/internal/sso/sessions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-internal-api-key': gmsKey },
    body: JSON.stringify({ email: EMAIL, initialRoles: resolvedRoles }),
  });
  const sessionBody = await sessionResp.json();
  if (sessionResp.status !== 200 || !sessionBody.success) throw new Error('GMS session mint failed: ' + JSON.stringify(sessionBody));

  const decoded = decodeJwt(sessionBody.data.accessToken);
  const tokenRoles = decoded?.roles ?? [];
  console.log('Minted GMS session JWT roles:', JSON.stringify(tokenRoles));

  const { rows: after } = await client.query(
    `SELECT r.name FROM users u JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id WHERE lower(u.email) = lower($1) ORDER BY r.name`,
    [EMAIL],
  );
  console.log('GMS local roles after (unchanged, as designed):', after.map((r) => r.name));

  const ok = tokenRoles.includes(NEW_SSO_ROLE)
    && !tokenRoles.includes(localRolesBefore[0])
    && JSON.stringify(after.map((r) => r.name).sort()) === JSON.stringify(localRolesBefore.sort());

  await client.end();
  console.log('\nRESULT:', ok ? 'PASS' : 'FAIL');
  if (!ok) process.exit(1);
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });
