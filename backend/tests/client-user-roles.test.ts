import { afterAll, afterEach, describe, expect, it } from '@jest/globals';
import { pool } from '../src/db/pool.js';
import { getGrantedRoles, listGrantedRolesForClient, setGrantedRoles } from '../src/auth/client-user-roles.js';

// Real DB integration test against the local `idp` database (matches the
// convention already used by DMS's and GMS's own Jest suites — this codebase
// verifies against a live database rather than mocking the query layer).
// This is the per-user role-grant mechanism GMS's admin UI writes through to
// (setSsoGrantedRoles) and both GMS's native-login fix and GMS's bridged-login
// path read from — one of the platform's actual highest-risk, least-tested
// surfaces per the gap register.

const TEST_EMAIL = 'jest-fixture-client-user-roles@example.invalid';
const CLIENT_ID = 'gms';

async function cleanup() {
  await pool.query('DELETE FROM idp_client_user_roles WHERE email = $1', [TEST_EMAIL]);
}

describe('client-user-roles', () => {
  afterEach(cleanup);
  afterAll(async () => {
    await cleanup();
    await pool.end();
  });

  it('returns an empty array when no grant exists', async () => {
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual([]);
  });

  it('grants roles, is case-insensitive on email, and reads them back sorted', async () => {
    await setGrantedRoles(TEST_EMAIL.toUpperCase(), CLIENT_ID, ['reception', 'admin'], 'jest-test');
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual(['admin', 'reception']);
  });

  it('replaces the whole grant set on a second call rather than appending', async () => {
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['admin'], 'jest-test');
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['host'], 'jest-test');
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual(['host']);
  });

  it('revoking every grant (empty array) is indistinguishable from never having granted one', async () => {
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['reception'], 'jest-test');
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, [], 'jest-test');
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual([]);
  });

  it('de-duplicates repeated role names in the same call', async () => {
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['admin', 'admin', 'admin'], 'jest-test');
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual(['admin']);
  });

  it('rejects a role name that is not in the client\'s role catalog, and writes nothing', async () => {
    await expect(
      setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['not_a_real_role'], 'jest-test'),
    ).rejects.toThrow(/Unknown role/);
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual([]);
  });

  it('rejects the whole batch if any one role in it is invalid (all-or-nothing)', async () => {
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['admin'], 'jest-test');
    await expect(
      setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['reception', 'not_a_real_role'], 'jest-test'),
    ).rejects.toThrow(/Unknown role/);
    // The pre-existing grant must be untouched - the failed call must not have
    // partially applied (this is exactly what the DELETE-then-INSERT-inside-a-
    // transaction structure in setGrantedRoles is supposed to guarantee).
    expect(await getGrantedRoles(TEST_EMAIL, CLIENT_ID)).toEqual(['admin']);
  });

  it('a grant for a different client_id does not leak into this client\'s results', async () => {
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['admin'], 'jest-test');
    expect(await getGrantedRoles(TEST_EMAIL, 'edams')).toEqual([]);
  });

  it('listGrantedRolesForClient surfaces the grant with its metadata', async () => {
    await setGrantedRoles(TEST_EMAIL, CLIENT_ID, ['host'], 'jest-test-operator');
    const all = await listGrantedRolesForClient(CLIENT_ID);
    const mine = all.filter((g) => g.email === TEST_EMAIL);
    expect(mine).toEqual([
      expect.objectContaining({ email: TEST_EMAIL, clientId: CLIENT_ID, roleName: 'host', grantedBy: 'jest-test-operator' }),
    ]);
  });
});
