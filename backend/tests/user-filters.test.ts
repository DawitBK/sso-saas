import { buildUserListFilter, parseRoleFilter, userOrderBy } from '../src/admin/services/user-filters.js';

const ADMIN_GROUP = 'CN=EDAMS_Admins,OU=Groups,DC=example,DC=com';
const base = { adminGroup: ADMIN_GROUP };

describe('parseRoleFilter', () => {
  it('accepts idp, dms and gms roles', () => {
    expect(parseRoleFilter('idp:admin')).toEqual({ system: 'idp', role: 'admin' });
    expect(parseRoleFilter('dms:RECORDS_OFFICER')).toEqual({ system: 'dms', role: 'RECORDS_OFFICER' });
    expect(parseRoleFilter('gms:super_host')).toEqual({ system: 'gms', role: 'super_host' });
  });

  it('rejects anything else, including attempts to smuggle SQL or an unknown system', () => {
    for (const bad of [undefined, '', 'admin', ':admin', 'xyz:admin', 'dms:', "dms:A'; DROP TABLE x;--", 'gms:a b', 'dms:' + 'A'.repeat(65), 42]) {
      expect(parseRoleFilter(bad)).toBeNull();
    }
  });
});

describe('buildUserListFilter', () => {
  it('always excludes the platform administrator, whatever else is asked', () => {
    for (const input of [
      base,
      { ...base, q: 'x' },
      { ...base, client: 'gms', role: { system: 'gms' as const, role: 'host' } },
      { ...base, role: { system: 'idp' as const, role: 'admin' } },
      { ...base, role: { system: 'dms' as const, role: 'EXECUTIVE' }, dmsGroupDns: ['CN=g'] },
    ]) {
      expect(buildUserListFilter(input).where).toContain('NOT u.is_platform_admin');
    }
  });

  it('with no filters is just the exclusion', () => {
    const f = buildUserListFilter(base);
    expect(f.params).toEqual([]);
    expect(f.where).toBe('WHERE NOT u.is_platform_admin');
  });

  it('numbers its parameters in order and never inlines a value', () => {
    const f = buildUserListFilter({ ...base, q: "o'brien", status: 'active', source: 'local', client: 'gms', role: { system: 'gms', role: 'host' } });
    expect(f.params).toEqual(["o'brien", 'local', 'gms', 'host']);
    expect(f.where).toContain('$1');
    expect(f.where).toContain('$4');
    expect(f.where).not.toContain("o'brien");
    expect(f.where).toContain('u.is_active = TRUE');
  });

  it('ignores unknown status and source values', () => {
    const f = buildUserListFilter({ ...base, status: 'banana', source: 'carrier-pigeon' });
    expect(f.where).toBe('WHERE NOT u.is_platform_admin');
    expect(f.params).toEqual([]);
  });

  it('the client filter follows the portal rule: an ungated client is open to everyone', () => {
    const f = buildUserListFilter({ ...base, client: 'edams' });
    expect(f.where).toContain('NOT EXISTS (SELECT 1 FROM idp_app_entitlements WHERE relying_party = $1)');
    expect(f.where).toContain('OR EXISTS');
    expect(buildUserListFilter({ ...base, client: 'portal' }).where).toBe('WHERE NOT u.is_platform_admin');
  });

  it('a GMS role honours the per-user grant before any group mapping', () => {
    const f = buildUserListFilter({ ...base, role: { system: 'gms', role: 'host' } });
    expect(f.where).toContain('idp_client_user_roles');
    expect(f.where).toContain('idp_gms_role_mappings');
    // the group-mapping branch only applies when the user has NO per-user grant
    expect(f.where).toMatch(/NOT EXISTS \(SELECT 1 FROM idp_client_user_roles/);
  });

  it('a DMS role uses the group list DMS supplied; none means nobody (and is not a SQL error)', () => {
    const some = buildUserListFilter({ ...base, role: { system: 'dms', role: 'AUDITOR' }, dmsGroupDns: ['CN=a', 'CN=b'] });
    expect(some.params).toEqual([['CN=a', 'CN=b']]);
    expect(some.where).toContain('ANY($1::text[])');
    const none = buildUserListFilter({ ...base, role: { system: 'dms', role: 'AUDITOR' }, dmsGroupDns: [] });
    expect(none.where).toContain('FALSE');
    expect(none.params).toEqual([]);
  });

  it('the IdP administrator filter matches membership of the admin group', () => {
    const f = buildUserListFilter({ ...base, role: { system: 'idp', role: 'admin' } });
    expect(f.params).toEqual([ADMIN_GROUP]);
  });
});

describe('two-factor filter', () => {
  it('enrolled and not enrolled become plain column tests with no parameter', () => {
    expect(buildUserListFilter({ ...base, mfa: 'enrolled' }).where).toContain('u.totp_enabled = TRUE');
    expect(buildUserListFilter({ ...base, mfa: 'not_enrolled' }).where).toContain('u.totp_enabled = FALSE');
    expect(buildUserListFilter({ ...base, mfa: 'enrolled' }).params).toEqual([]);
  });
  it('anything else adds nothing, and the platform administrator is still excluded', () => {
    const f = buildUserListFilter({ ...base, mfa: "enrolled'; DROP TABLE idp_users;--" });
    expect(f.where).toBe('WHERE NOT u.is_platform_admin');
  });
});

describe('userOrderBy', () => {
  it('maps each allowed sort to a fixed expression with a stable tie-break', () => {
    expect(userOrderBy('email', 'asc')).toBe('u.email ASC');
    expect(userOrderBy('email', 'desc')).toBe('u.email DESC');
    expect(userOrderBy('status', 'desc')).toBe('u.is_active DESC, u.email ASC');
    expect(userOrderBy('last_login', 'desc')).toBe('u.last_login_at DESC NULLS LAST, u.email ASC');
    expect(userOrderBy('created', 'asc')).toBe('u.created_at ASC, u.email ASC');
    expect(userOrderBy('name', 'asc')).toContain('lower(coalesce(u.family_name');
  });
  it('an unknown or hostile value falls back to the email, ascending', () => {
    expect(userOrderBy('1; DROP TABLE idp_users', 'asc; --')).toBe('u.email ASC');
    expect(userOrderBy(undefined, undefined)).toBe('u.email ASC');
    expect(userOrderBy({}, [])).toBe('u.email ASC');
  });
});

