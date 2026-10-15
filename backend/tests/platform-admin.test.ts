/**
 * The platform administrator in SSO (auth/platform-admin.ts): the pure parts and
 * the route guard. The database and HTTP behaviour is proved against a real
 * database by test-scripts/verify-platform-admin.ts.
 */

const PA = '00000000-0000-0000-0000-00000000aaaa';
const OTHER = '00000000-0000-0000-0000-00000000bbbb';

const mockQuery = jest.fn();
jest.mock('../src/db/pool.js', () => ({ pool: { query: (...a: unknown[]) => mockQuery(...a) } }));
jest.mock('../src/config.js', () => ({ IDP_CONFIG: { platformAdminPepper: 'unit-test-pepper' } }));

import {
  PLATFORM_ADMIN_ROLE,
  findPlatformAdminForLogin,
  guardPlatformAdminUserParam,
  invalidatePlatformAdminCache,
  isPlatformAdminEmail,
  isPlatformAdminId,
  isPlatformAdminSession,
  platformAdminPseudonym,
  visibleUserSql,
  withoutPlatformAdminRole,
  withoutPlatformAdminRoleName,
} from '../src/auth/platform-admin.js';

beforeEach(() => {
  mockQuery.mockReset();
  invalidatePlatformAdminCache();
});

describe('pseudonym', () => {
  it('is deterministic and ignores case and surrounding spaces in the email', () => {
    const a = platformAdminPseudonym('Owner@Example.com', 'p');
    expect(platformAdminPseudonym('  owner@example.com ', 'p')).toBe(a);
  });

  it('differs by pepper and by email, and cannot be mistaken for a real mailbox', () => {
    const a = platformAdminPseudonym('owner@example.com', 'p1');
    expect(platformAdminPseudonym('owner@example.com', 'p2')).not.toBe(a);
    expect(platformAdminPseudonym('other@example.com', 'p1')).not.toBe(a);
    expect(a).toMatch(/^pa-[0-9a-f]{32}@platform\.invalid$/);
  });

  it('does not contain any part of the email', () => {
    const a = platformAdminPseudonym('dawitbk01@gmail.com', 'p');
    expect(a).not.toContain('daniel');
    expect(a).not.toContain('gmail');
  });
});

describe('who is the platform admin (cached)', () => {
  beforeEach(() => mockQuery.mockResolvedValue({ rows: [{ id: PA, email: 'PA-abc@platform.invalid' }] }));

  it('matches by id and by stored email, case-insensitively', async () => {
    expect(await isPlatformAdminId(PA)).toBe(true);
    expect(await isPlatformAdminId(OTHER)).toBe(false);
    expect(await isPlatformAdminId(undefined)).toBe(false);
    expect(await isPlatformAdminEmail('pa-ABC@platform.invalid')).toBe(true);
    expect(await isPlatformAdminEmail('someone@else.com')).toBe(false);
    expect(mockQuery).toHaveBeenCalledTimes(1);
  });

  it('a console session is the platform admin only if its account is', async () => {
    expect(await isPlatformAdminSession({ accountId: PA })).toBe(true);
    expect(await isPlatformAdminSession({ accountId: OTHER })).toBe(false);
    expect(await isPlatformAdminSession(undefined)).toBe(false);
  });
});

describe('login lookup', () => {
  it('looks for the typed address AND its pseudonym, among platform admins only', async () => {
    mockQuery.mockResolvedValue({ rows: [{ id: PA, email: 'whatever' }] });
    const found = await findPlatformAdminForLogin('  Owner@Example.com ');
    expect(found).toEqual({ id: PA, email: 'whatever' });
    const [sql, params] = mockQuery.mock.calls[0];
    expect(sql).toContain('is_platform_admin');
    expect(params[0]).toEqual(['owner@example.com', platformAdminPseudonym('owner@example.com', 'unit-test-pepper')]);
  });

  it('returns null for an ordinary address, and for an empty one without asking', async () => {
    mockQuery.mockResolvedValue({ rows: [] });
    expect(await findPlatformAdminForLogin('nobody@example.com')).toBeNull();
    mockQuery.mockClear();
    expect(await findPlatformAdminForLogin('   ')).toBeNull();
    expect(mockQuery).not.toHaveBeenCalled();
  });
});

describe('role lists', () => {
  it('never offer the platform-admin role', () => {
    expect(withoutPlatformAdminRoleName(['SYSTEM_ADMIN', PLATFORM_ADMIN_ROLE, 'EMPLOYEE'])).toEqual(['SYSTEM_ADMIN', 'EMPLOYEE']);
    expect(withoutPlatformAdminRole([{ role_name: PLATFORM_ADMIN_ROLE }, { name: 'X' }]).map((r) => r.name)).toEqual(['X']);
  });
  it('the visibility predicate names the flag', () => {
    expect(visibleUserSql('u')).toBe('NOT u.is_platform_admin');
  });
});

describe('guardPlatformAdminUserParam', () => {
  const run = async (target: string, viewer?: string) => {
    mockQuery.mockResolvedValue({ rows: [{ id: PA, email: 'x@platform.invalid' }] });
    const res: any = {};
    const sendNotFound = jest.fn();
    const next = jest.fn();
    await guardPlatformAdminUserParam(sendNotFound)({ adminSession: viewer ? { accountId: viewer } : undefined } as any, res, next, target);
    return { sendNotFound, next };
  };

  it('answers "not found" for a platform admin target', async () => {
    const { sendNotFound, next } = await run(PA, OTHER);
    expect(sendNotFound).toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });
  it('lets ordinary targets through', async () => {
    const { sendNotFound, next } = await run(OTHER, OTHER);
    expect(sendNotFound).not.toHaveBeenCalled();
    expect(next).toHaveBeenCalledWith();
  });
  it('lets the platform admin open itself', async () => {
    const { next } = await run(PA, PA);
    expect(next).toHaveBeenCalledWith();
  });
});
