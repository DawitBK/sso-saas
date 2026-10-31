import { pool } from '../src/db/pool.js';
import {
  accountHasAppAccess,
  appAccessOf,
  appRolesFor,
  ensureAppRolesScope,
  managedCatalog,
  managedClientIds,
  resetManagedClientsCache,
} from '../src/auth/app-roles.js';
import { findAccount } from '../src/auth/account.js';
import { setGrantedRoles } from '../src/auth/client-user-roles.js';
import { parseAppRolesInput } from '../src/admin/app-access.js';
import { replaceClientCatalog } from '../src/admin/app-role-catalog.js';
import { seedClientRoles } from '../src/oidc/client-roles-config.js';
import { getClientDetails } from '../src/oidc/client-admin.js';
import { IDP_CONFIG } from '../src/config.js';
import { buildUserListFilter, parseRoleFilter } from '../src/admin/services/user-filters.js';

// Needs the IdP's database (DATABASE_URL), like the other *-db tests. Everything it creates is prefixed "jest-approles" and removed again.
const APP = 'jest-approles-shop';
const OTHER = 'jest-approles-other';
const email = (n: string) => `jest-approles-${n}@example.invalid`;

async function addUser(name: string, active = true): Promise<string> {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, source, is_active) VALUES ($1, TRUE, 'Jest', $2, 'local', $3) RETURNING id`,
    [email(name), name, active],
  );
  return rows[0]!.id;
}

async function cleanup() {
  await pool.query(`DELETE FROM idp_client_user_roles WHERE client_id LIKE 'jest-approles-%' OR email LIKE 'jest-approles-%'`);
  await pool.query(`DELETE FROM idp_client_roles WHERE client_id LIKE 'jest-approles-%'`);
  await pool.query(`DELETE FROM idp_clients WHERE client_id LIKE 'jest-approles-%'`);
  await pool.query(`DELETE FROM idp_users WHERE email LIKE 'jest-approles-%'`);
  resetManagedClientsCache();
}

beforeAll(async () => {
  await cleanup();
  for (const [id, scope] of [[APP, 'openid profile email'], [OTHER, null]] as const) {
    await pool.query(
      `INSERT INTO idp_clients (client_id, client_secret, redirect_uris, name, scope) VALUES ($1, 'jest-secret-jest-secret', ARRAY['https://x.example.invalid/cb'], $1, $2)`,
      [id, scope],
    );
  }
});

afterAll(async () => {
  await cleanup();
  await pool.end();
});

describe('a client becomes managed when its role catalog has rows', () => {
  it('is not managed before it has roles, and the claim is left out for it', async () => {
    resetManagedClientsCache();
    expect((await managedClientIds()).has(APP)).toBe(false);
    expect(await appRolesFor(email('a'), APP)).toBeUndefined();
    expect(await accountHasAppAccess('00000000-0000-0000-0000-000000000000', APP)).toBe(true);
  });

  it('seeds roles from CLIENT_ROLES_JSON without ever overwriting an edit, and lets the client ask for app_roles', async () => {
    await seedClientRoles(JSON.stringify({ [APP]: [{ name: 'owner', display_name: 'Owner' }, { name: 'cashier', display_name: 'Cashier' }] }));
    expect((await managedClientIds()).has(APP)).toBe(true);
    // An administrator renames a role; the next boot's seed must not undo it.
    await pool.query(`UPDATE idp_client_roles SET display_name = 'Shop owner' WHERE client_id = $1 AND role_name = 'owner'`, [APP]);
    await seedClientRoles(JSON.stringify({ [APP]: [{ name: 'owner', display_name: 'Owner' }, { name: 'cashier' }, { name: 'manager' }] }));
    const catalog = (await managedCatalog()).find((c) => c.clientId === APP)!;
    expect(catalog.roles.map((r) => [r.roleName, r.displayName])).toEqual([['owner', 'Shop owner'], ['cashier', 'Cashier'], ['manager', 'manager']]);
    const { rows } = await pool.query<{ scope: string }>('SELECT scope FROM idp_clients WHERE client_id = $1', [APP]);
    expect(rows[0]!.scope.split(' ')).toEqual(['openid', 'profile', 'email', 'app_roles']);
  });

  it('adds the scope once, leaves an unrestricted client alone and keeps an operator\'s narrower list', async () => {
    await ensureAppRolesScope(APP);
    await ensureAppRolesScope(APP);
    expect((await pool.query<{ scope: string }>('SELECT scope FROM idp_clients WHERE client_id = $1', [APP])).rows[0]!.scope).toBe('openid profile email app_roles');
    await ensureAppRolesScope(OTHER);
    expect((await pool.query<{ scope: string | null }>('SELECT scope FROM idp_clients WHERE client_id = $1', [OTHER])).rows[0]!.scope).toBeNull();
  });
});

describe('access follows the roles a person holds', () => {
  it('is none without a role, the roles with them, and never for an inactive account', async () => {
    const id = await addUser('person');
    expect(await appRolesFor(email('person'), APP)).toEqual([]);
    expect(await accountHasAppAccess(id, APP)).toBe(false);

    await setGrantedRoles(email('person'), APP, ['cashier', 'manager'], 'jest');
    expect(await appRolesFor(email('person'), APP)).toEqual(['cashier', 'manager']);
    expect(await accountHasAppAccess(id, APP)).toBe(true);
    expect(await appAccessOf(email('person'))).toMatchObject({ [APP]: ['cashier', 'manager'] });
    // Another application's roles never leak into this one's claim.
    expect(await appRolesFor(email('person'), OTHER)).toBeUndefined();

    await pool.query('UPDATE idp_users SET is_active = FALSE WHERE id = $1', [id]);
    expect(await accountHasAppAccess(id, APP)).toBe(false);
  });

  it('refuses a role that is not in the catalog', async () => {
    await expect(setGrantedRoles(email('person'), APP, ['wizard'], 'jest')).rejects.toThrow(/Unknown role/);
  });
});

describe('the app_roles claim', () => {
  const ask = async (accountId: string, clientId?: string) => {
    const account = await findAccount((clientId ? { oidc: { client: { clientId } } } : {}) as never, accountId);
    return account!.claims('id_token', 'openid profile email app_roles', {}, []) as Promise<Record<string, unknown>>;
  };

  it('carries the roles of the asking application only, and is left out for any other client', async () => {
    const id = await addUser('claimant');
    await setGrantedRoles(email('claimant'), APP, ['manager'], 'jest');
    expect((await ask(id, APP)).app_roles).toEqual(['manager']);
    expect('app_roles' in (await ask(id, OTHER))).toBe(false);
    expect('app_roles' in (await ask(id, 'gms'))).toBe(false);
    expect('app_roles' in (await ask(id))).toBe(false);
  });

  it('is an empty list, not an absent claim, for a person with no role in a managed application', async () => {
    const id = await addUser('norole');
    expect((await ask(id, APP)).app_roles).toEqual([]);
  });
});

describe('parseAppRolesInput (what the App access panel sends)', () => {
  it('accepts managed applications with catalog roles, and treats absent as "leave alone"', async () => {
    expect(await parseAppRolesInput(undefined)).toEqual({ ok: true, value: {} });
    expect(await parseAppRolesInput({ [APP]: ['owner', 'owner'] })).toEqual({ ok: true, value: { [APP]: ['owner'] } });
    expect(await parseAppRolesInput({ [APP]: [] })).toEqual({ ok: true, value: { [APP]: [] } });
  });

  it('refuses an unmanaged application, an unknown role and the wrong shapes', async () => {
    for (const bad of [{ edams: ['SYSTEM_ADMIN'] }, { [OTHER]: ['x'] }, { [APP]: ['wizard'] }, { [APP]: 'owner' }, { [APP]: [1] }, ['owner'], 'owner']) {
      expect((await parseAppRolesInput(bad)).ok).toBe(false);
    }
  });
});

describe('editing the catalog', () => {
  it('adds, renames and reorders roles, and keeps the scope', async () => {
    const result = await replaceClientCatalog(APP, [
      { roleName: 'owner', displayName: 'Owner', sortOrder: 1 },
      { roleName: 'cashier', displayName: 'Till operator', sortOrder: 2 },
      { roleName: 'manager', sortOrder: 3 },
      { roleName: 'auditor', displayName: 'Auditor', sortOrder: 4 },
    ]);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.after.map((r) => [r.roleName, r.displayName])).toEqual([['owner', 'Owner'], ['cashier', 'Till operator'], ['manager', 'manager'], ['auditor', 'Auditor']]);
  });

  it('refuses to remove a role somebody holds, and says who', async () => {
    const result = await replaceClientCatalog(APP, [{ roleName: 'owner' }, { roleName: 'manager' }]);
    expect(result).toMatchObject({ ok: false, status: 409, code: 'ERR-ROLE-IN-USE' });
    if (!result.ok) expect(result.message).toMatch(/"cashier" \(1 person holds it\)/);
  });

  it('removes a role nobody holds', async () => {
    await setGrantedRoles(email('person'), APP, [], 'jest');
    const result = await replaceClientCatalog(APP, [{ roleName: 'owner' }, { roleName: 'cashier' }, { roleName: 'manager' }]);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.after.map((r) => r.roleName)).toEqual(['owner', 'cashier', 'manager']);
  });

  it('refuses bad input, the built-in systems and unknown clients', async () => {
    expect(await replaceClientCatalog(APP, [])).toMatchObject({ ok: false, status: 400 });
    expect(await replaceClientCatalog(APP, [{ roleName: 'bad name' }])).toMatchObject({ ok: false, status: 400 });
    expect(await replaceClientCatalog(APP, [{ roleName: 'a' }, { roleName: 'a' }])).toMatchObject({ ok: false, status: 400 });
    expect(await replaceClientCatalog('gms', [{ roleName: 'x' }])).toMatchObject({ ok: false, status: 409, code: 'ERR-CATALOG-PROTECTED' });
    expect(await replaceClientCatalog('jest-approles-missing', [{ roleName: 'x' }])).toMatchObject({ ok: false, status: 404 });
  });
});

describe('the console treats every managed application like DMS and GMS', () => {
  it('lists the Users who hold a given role in an application, and only them', async () => {
    const holder = await addUser('filter-holder');
    const other = await addUser('filter-other');
    await addUser('filter-none');
    await setGrantedRoles(email('filter-holder'), APP, ['owner'], 'jest');
    await setGrantedRoles(email('filter-other'), APP, ['manager'], 'jest');
    const ids = async (role: string, extra: Record<string, string> = {}): Promise<string[]> => {
      const f = buildUserListFilter({ adminGroup: 'CN=none', role: parseRoleFilter(role), q: 'jest-approles-filter', ...extra });
      const { rows } = await pool.query<{ id: string }>(`SELECT u.id FROM idp_users u ${f.where}`, f.params);
      return rows.map((r) => r.id).sort();
    };
    expect(await ids(`app:${APP}:owner`)).toEqual([holder]);
    expect(await ids(`app:${APP}:manager`)).toEqual([other]);
    expect(await ids(`app:${APP}:cashier`)).toEqual([]);
    // "Can sign in to" for the same application is the same people.
    expect(await ids('', { client: APP })).toEqual([holder, other].sort());
  });

  it('describes a managed application by how it is wired, and leaves the built-in systems own descriptions alone', async () => {
    // The console lists only clients that are in the configured seed, so the two test clients are put there for this test.
    const added = [APP, OTHER].map((id) => ({ client_id: id, name: id, redirect_uris: ['https://x.example.invalid/cb'], post_logout_redirect_uris: [] }));
    IDP_CONFIG.clientSeed.push(...(added as never[]));
    const entitled = async () => null;
    const app = (await getClientDetails(APP, entitled))!;
    expect(app.rolesScope).toBe('app_roles');
    expect(app.pattern).toMatch(/app_roles claim/);
    expect(app.secretNote).toMatch(/keeps its own copy/);
    const unmanaged = (await getClientDetails(OTHER, async () => null))!;
    expect(unmanaged.pattern).toBe('Registered client.');
    IDP_CONFIG.clientSeed.splice(IDP_CONFIG.clientSeed.length - added.length, added.length);
    const gms = await getClientDetails('gms', entitled);
    if (gms) expect(gms.rolesScope).toBe('gms_roles');
  });
});
