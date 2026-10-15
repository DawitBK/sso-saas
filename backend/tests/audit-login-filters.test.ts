/**
 * The Audit and Sign-ins filters (admin/services/audit-filters.ts, login-filters.ts): the SQL they build, and that Postgres accepts it.
 * The SQL shape is checked without a database; the "runs" tests execute each combination read-only against the dev `idp` database.
 */
import { buildAuditFilter } from '../src/admin/services/audit-filters.js';
import { buildLoginFilter } from '../src/admin/services/login-filters.js';
import { listAudit, countAudit, distinctAuditActions } from '../src/admin/audit.js';
import { pool } from '../src/db/pool.js';

afterAll(async () => {
  await pool.end();
});

describe('buildAuditFilter', () => {
  it('always keeps the platform administrator out, whatever else is asked', () => {
    for (const input of [{}, { q: 'x' }, { action: 'user.' }, { actor: 'a@b.co' }, { from: '2026-01-01', to: '2026-02-01' }, { q: 'platform', actor: 'platform' }]) {
      const f = buildAuditFilter(input);
      expect(f.where).toContain('lower(actor_email) NOT IN');
      expect(f.where).toContain('lower(target) NOT IN');
      expect(f.where).toContain("detail->>'userId'");
    }
  });

  it('numbers parameters in order and never inlines a value', () => {
    const f = buildAuditFilter({ q: "o'brien", action: 'user.disable', actor: 'Admin@Example.com', from: '2026-01-01', to: '2026-01-31' });
    expect(f.params).toEqual(["o'brien", 'user.disable', 'admin@example.com', '2026-01-01', '2026-01-31']);
    expect(f.where).not.toContain("o'brien");
    for (let i = 1; i <= 5; i += 1) expect(f.where).toContain(`$${i}`);
  });

  it('an action ending in a dot is a family, with underscores kept literal', () => {
    const family = buildAuditFilter({ action: 'signing_key.' });
    expect(family.where).toContain('action LIKE $1');
    expect(family.params).toEqual(['signing\\_key.%']);
    const exact = buildAuditFilter({ action: 'user.disable' });
    expect(exact.where).toContain('action = $1');
  });

  it('refuses an action that is not shaped like one (no SQL, no wildcards)', () => {
    for (const bad of ["user.disable'; DROP TABLE idp_users;--", '%', 'user disable', 'USER.DISABLE; x']) {
      expect(buildAuditFilter({ action: bad }).params).toEqual([]);
    }
  });
});

describe('buildLoginFilter', () => {
  it('always excludes anything naming the platform administrator', () => {
    for (const input of [{}, { success: false }, { q: 'x' }, { reason: 'locked' }]) {
      expect(buildLoginFilter(input).where).toContain('NOT u.is_platform_admin');
    }
  });

  it('success and failure become a parameter, "both" adds nothing', () => {
    expect(buildLoginFilter({ success: true }).params).toEqual([true]);
    expect(buildLoginFilter({ success: false }).params).toEqual([false]);
    expect(buildLoginFilter({ success: null }).params).toEqual([]);
  });

  it('a reason is exact and must look like a reason code', () => {
    expect(buildLoginFilter({ reason: 'mfa_failed' }).params).toEqual(['mfa_failed']);
    expect(buildLoginFilter({ reason: "x'; DROP TABLE idp_login_events;--" }).params).toEqual([]);
    expect(buildLoginFilter({ reason: 'Not A Code' }).params).toEqual([]);
  });

  it('the search matches the email or the address', () => {
    const f = buildLoginFilter({ q: '10.0.0.5' });
    expect(f.where).toContain('e.email ILIKE');
    expect(f.where).toContain('e.ip ILIKE');
    expect(f.params).toEqual(['10.0.0.5']);
  });
});

describe('against the real database', () => {
  it('every audit filter combination is valid SQL and returns rows or none', async () => {
    const combos = [{}, { q: 'user' }, { action: 'user.' }, { action: 'user.disable' }, { actor: 'nobody@example.invalid' }, { from: '2026-01-01', to: '2026-12-31' }, { q: 'a', action: 'setting.', actor: 'platform', from: '2026-01-01', to: '2026-12-31' }];
    for (const input of combos) {
      const rows = await listAudit(input, 5, 0);
      expect(Array.isArray(rows)).toBe(true);
      expect(typeof (await countAudit(input))).toBe('number');
    }
    const actions = await distinctAuditActions();
    expect(Array.isArray(actions)).toBe(true);
  });

  it('a family filter returns only that family', async () => {
    const rows = await listAudit({ action: 'user.' }, 50, 0);
    for (const r of rows) expect(r.action.startsWith('user.')).toBe(true);
  });

  it('every sign-in filter combination is valid SQL', async () => {
    const combos = [{}, { success: true }, { success: false, q: 'a' }, { reason: 'invalid_credentials' }, { from: '2026-01-01', to: '2026-12-31', success: false, reason: 'locked', q: '10.' }];
    for (const input of combos) {
      const f = buildLoginFilter(input);
      const { rows } = await pool.query(
        `SELECT e.id FROM idp_login_events e LEFT JOIN idp_users u ON lower(u.email) = e.email ${f.where} ORDER BY e.id DESC LIMIT $${f.params.length + 1}`,
        [...f.params, 5],
      );
      expect(Array.isArray(rows)).toBe(true);
    }
  });
});
