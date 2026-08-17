import { afterAll, afterEach, describe, expect, it } from '@jest/globals';
import { pool } from '../src/db/pool.js';
import { setGrantedRoles } from '../src/auth/client-user-roles.js';
import { resolveGmsRoles, resolveGmsRolesFromGroups } from '../src/auth/client-role-claims.js';

// This is the precedence logic that closed SSO-GAP-004 / PLATFORM-GAP-012:
// explicit per-user grant > AD group mapping > 'guest' default. Getting this
// order wrong silently defeats the whole point of the per-user-grant
// mechanism, so it's covered directly rather than only indirectly through the
// login flows that consume it.

const TEST_EMAIL = 'jest-fixture-role-claims@example.invalid';
const TEST_GROUP_DN = 'CN=jest-fixture-group,DC=example,DC=invalid';

async function cleanup() {
  await pool.query('DELETE FROM idp_client_user_roles WHERE email = $1', [TEST_EMAIL]);
  await pool.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [TEST_GROUP_DN]);
}

describe('resolveGmsRoles precedence', () => {
  afterEach(cleanup);

  it('falls back to the guest default when there is no grant and no group match', async () => {
    expect(await resolveGmsRoles(TEST_EMAIL, [])).toEqual(['guest']);
    expect(await resolveGmsRoles(TEST_EMAIL, ['CN=some-unmapped-group,DC=example,DC=invalid'])).toEqual(['guest']);
  });

  it('resolves via AD group mapping when no explicit per-user grant exists', async () => {
    await pool.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2)', [TEST_GROUP_DN, 'reception']);
    expect(await resolveGmsRoles(TEST_EMAIL, [TEST_GROUP_DN])).toEqual(['reception']);
  });

  it('an explicit per-user grant wins over a matching AD group mapping', async () => {
    await pool.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2)', [TEST_GROUP_DN, 'reception']);
    await setGrantedRoles(TEST_EMAIL, 'gms', ['admin'], 'jest-test');
    // Precedence is the whole point: even though the group mapping says
    // 'reception', the explicit grant ('admin') must be what's returned.
    expect(await resolveGmsRoles(TEST_EMAIL, [TEST_GROUP_DN])).toEqual(['admin']);
  });

  it('an explicit per-user grant applies even with no AD groups at all', async () => {
    await setGrantedRoles(TEST_EMAIL, 'gms', ['host'], 'jest-test');
    expect(await resolveGmsRoles(TEST_EMAIL, [])).toEqual(['host']);
  });

  it('revoking the explicit grant falls back to the group mapping again, not to guest', async () => {
    await pool.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2)', [TEST_GROUP_DN, 'reception']);
    await setGrantedRoles(TEST_EMAIL, 'gms', ['admin'], 'jest-test');
    await setGrantedRoles(TEST_EMAIL, 'gms', [], 'jest-test');
    expect(await resolveGmsRoles(TEST_EMAIL, [TEST_GROUP_DN])).toEqual(['reception']);
  });
});

describe('resolveGmsRolesFromGroups', () => {
  afterEach(cleanup);

  it('returns the guest default for an empty group list', async () => {
    expect(await resolveGmsRolesFromGroups([])).toEqual(['guest']);
  });

  it('returns every distinct role mapped across multiple matching groups, sorted', async () => {
    const groupB = 'CN=jest-fixture-group-b,DC=example,DC=invalid';
    await pool.query('INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, $2), ($3, $4)', [
      TEST_GROUP_DN, 'reception', groupB, 'host',
    ]);
    try {
      expect(await resolveGmsRolesFromGroups([TEST_GROUP_DN, groupB])).toEqual(['host', 'reception']);
    } finally {
      await pool.query('DELETE FROM idp_gms_role_mappings WHERE group_dn = $1', [groupB]);
    }
  });

  afterAll(async () => {
    await cleanup();
    await pool.end();
  });
});
