/**
 * applyAccess (admin/access.ts) when DMS cannot be reached: the IdP-side entitlement and the
 * DMS-side role mapping live in two databases, so a failed call must leave BOTH exactly as they
 * were - never "entitled in SSO with no mapping in DMS" and never "mapping in DMS behind an
 * entitlement SSO already removed". Runs against the dev `idp` database with a scratch user
 * and group; DMS, session revocation and the audit writer are mocked.
 */
const mockGetMapping = jest.fn();
const mockPutMapping = jest.fn();
const mockRevoke = jest.fn();

jest.mock('../src/admin/dms-internal-client.js', () => {
  class DmsInternalApiError extends Error {
    status: number;
    code: string;
    constructor(message: string, status: number, code: string) {
      super(message);
      this.status = status;
      this.code = code;
    }
  }
  return {
    DmsInternalApiError,
    getDmsRoleMapping: (...a: unknown[]) => mockGetMapping(...a),
    putDmsRoleMapping: (...a: unknown[]) => mockPutMapping(...a),
    listDmsRoles: jest.fn(),
    getDmsRolePermissions: jest.fn(),
    putDmsRolePermissions: jest.fn(),
    getDmsUserOverrides: jest.fn(),
    putDmsUserOverrides: jest.fn(),
    listDmsMappedGroups: jest.fn(),
    getDmsUserStatusByEmail: jest.fn(),
    listDmsDepartments: jest.fn(),
    putDmsUserDepartments: jest.fn(),
  };
});
jest.mock('../src/auth/revoke.js', () => ({ revokeAllSessions: (...a: unknown[]) => mockRevoke(...a) }));
jest.mock('../src/admin/audit.js', () => ({
  writeAudit: jest.fn(async () => undefined),
  recentAudit: jest.fn(),
  verifyAuditChain: jest.fn(),
}));

import { pool } from '../src/db/pool.js';
import { IDP_CONFIG } from '../src/config.js';
import { applyAccess } from '../src/admin/access.js';
import { DmsInternalApiError } from '../src/admin/dms-internal-client.js';

const EMAIL = 'jest-fixture-apply-access@example.invalid';
let userId = '';
const DN = () => `CN=user:${userId},OU=Users,DC=example,DC=invalid`;
const fakeReq = { ip: '127.0.0.1', headers: {} } as never;
const savedKey = IDP_CONFIG.dmsInternalApiKey;

async function entitled(): Promise<boolean> {
  const { rowCount } = await pool.query("SELECT 1 FROM idp_app_entitlements WHERE relying_party = 'edams' AND group_dn = $1", [DN()]);
  return (rowCount ?? 0) > 0;
}

beforeAll(async () => {
  await pool.query('DELETE FROM idp_users WHERE email = $1', [EMAIL]);
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active)
     VALUES ($1, TRUE, 'Jest', 'Fixture', 'x', 'local', TRUE) RETURNING id`,
    [EMAIL],
  );
  userId = rows[0].id;
  (IDP_CONFIG as { dmsInternalApiKey: string }).dmsInternalApiKey = 'unit-test-key';
});

beforeEach(async () => {
  jest.resetAllMocks();
  mockGetMapping.mockResolvedValue({ groupDn: DN(), roleNames: [] });
  await pool.query("DELETE FROM idp_app_entitlements WHERE group_dn = $1", [DN()]);
});

afterAll(async () => {
  await pool.query("DELETE FROM idp_app_entitlements WHERE group_dn = $1", [DN()]);
  await pool.query('DELETE FROM idp_user_groups WHERE user_id = $1', [userId]);
  await pool.query('DELETE FROM idp_users WHERE id = $1', [userId]);
  (IDP_CONFIG as { dmsInternalApiKey: string | undefined }).dmsInternalApiKey = savedKey;
  await pool.end();
});

const unreachable = () => new DmsInternalApiError('Could not reach DMS', 503, 'ERR-DMS-UNREACHABLE');

describe('applyAccess with roles, DMS unreachable', () => {
  it('a NEW entitlement is rolled back, and the DMS error keeps its status and code', async () => {
    mockPutMapping.mockRejectedValue(unreachable());
    const err = await applyAccess(userId, EMAIL, DN(), ['APPROVER'], '', null, 'admin@example.invalid', fakeReq).catch((e) => e);
    expect(err).toBeInstanceOf(DmsInternalApiError);
    expect(err).toMatchObject({ status: 503, code: 'ERR-DMS-UNREACHABLE' });
    expect(err.message).toContain('access change was not applied');
    expect(await entitled()).toBe(false);
    expect(mockRevoke).not.toHaveBeenCalled();
  });

  it('a PRE-EXISTING entitlement survives a failed re-save (it used to be deleted by the compensation)', async () => {
    await pool.query("INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ('edams', $1)", [DN()]);
    mockGetMapping.mockResolvedValue({ groupDn: DN(), roleNames: ['APPROVER'] });
    mockPutMapping.mockRejectedValue(unreachable());
    await expect(applyAccess(userId, EMAIL, DN(), ['APPROVER', 'AUDITOR'], '', null, 'admin@example.invalid', fakeReq)).rejects.toMatchObject({
      code: 'ERR-DMS-UNREACHABLE',
    });
    expect(await entitled()).toBe(true);
  });

  it('success adds the entitlement and revokes sessions because access changed', async () => {
    mockPutMapping.mockResolvedValue({ groupDn: DN(), roleNames: ['APPROVER'] });
    await applyAccess(userId, EMAIL, DN(), ['APPROVER'], '', null, 'admin@example.invalid', fakeReq);
    expect(await entitled()).toBe(true);
    expect(mockRevoke).toHaveBeenCalledTimes(1);
  });
});

describe('applyAccess clearing DMS access, DMS unreachable', () => {
  it('fails with the entitlement still in place (DMS is written first)', async () => {
    await pool.query("INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ('edams', $1)", [DN()]);
    mockGetMapping.mockResolvedValue({ groupDn: DN(), roleNames: ['APPROVER'] });
    mockPutMapping.mockRejectedValue(unreachable());
    await expect(applyAccess(userId, EMAIL, DN(), [], '', null, 'admin@example.invalid', fakeReq)).rejects.toMatchObject({ code: 'ERR-DMS-UNREACHABLE' });
    expect(await entitled()).toBe(true);
    expect(mockRevoke).not.toHaveBeenCalled();
  });

  it('on success unmaps in DMS and drops the entitlement', async () => {
    await pool.query("INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ('edams', $1)", [DN()]);
    mockGetMapping.mockResolvedValue({ groupDn: DN(), roleNames: ['APPROVER'] });
    mockPutMapping.mockResolvedValue({ groupDn: DN(), roleNames: [] });
    await applyAccess(userId, EMAIL, DN(), [], '', null, 'admin@example.invalid', fakeReq);
    expect(mockPutMapping).toHaveBeenCalledWith(expect.anything(), DN(), [], 'admin@example.invalid', undefined);
    expect(await entitled()).toBe(false);
    expect(mockRevoke).toHaveBeenCalledTimes(1);
  });
});
