import { parseClientRoles } from '../src/oidc/client-roles-config.js';

describe('parseClientRoles (CLIENT_ROLES_JSON)', () => {
  it('means no managed application when absent or empty', () => {
    expect(parseClientRoles(undefined).size).toBe(0);
    expect(parseClientRoles('').size).toBe(0);
    expect(parseClientRoles('   ').size).toBe(0);
  });

  it('reads roles with display names and order, defaulting both', () => {
    const parsed = parseClientRoles(
      JSON.stringify({ 'retail-os': [{ name: 'owner', display_name: 'Owner', sort_order: 5 }, { name: 'cashier' }] }),
    );
    expect(parsed.get('retail-os')).toEqual([
      { name: 'owner', displayName: 'Owner', sortOrder: 5 },
      { name: 'cashier', displayName: 'cashier', sortOrder: 20 },
    ]);
  });

  it('refuses a list that is not an object, and the systems that have their own role flow', () => {
    expect(() => parseClientRoles('not json')).toThrow(/not valid JSON/);
    expect(() => parseClientRoles('[]')).toThrow(/JSON object/);
    for (const id of ['edams', 'gms', 'portal', 'idp-admin']) {
      expect(() => parseClientRoles(JSON.stringify({ [id]: [{ name: 'x' }] }))).toThrow(/own role flow/);
    }
  });

  it('refuses a bad client id, an empty list, a bad or repeated role name, and bad display names or orders', () => {
    expect(() => parseClientRoles(JSON.stringify({ 'Bad Id': [{ name: 'a' }] }))).toThrow(/client id/);
    expect(() => parseClientRoles(JSON.stringify({ app: [] }))).toThrow(/non-empty/);
    expect(() => parseClientRoles(JSON.stringify({ app: [{ name: 'has space' }] }))).toThrow(/name must be/);
    expect(() => parseClientRoles(JSON.stringify({ app: [{ name: '' }] }))).toThrow(/name must be/);
    expect(() => parseClientRoles(JSON.stringify({ app: [{ name: 'a' }, { name: 'a' }] }))).toThrow(/listed twice/);
    expect(() => parseClientRoles(JSON.stringify({ app: [{ name: 'a', display_name: '' }] }))).toThrow(/display_name/);
    expect(() => parseClientRoles(JSON.stringify({ app: [{ name: 'a', display_name: 'x'.repeat(81) }] }))).toThrow(/display_name/);
    expect(() => parseClientRoles(JSON.stringify({ app: [{ name: 'a', sort_order: 1.5 }] }))).toThrow(/whole number/);
  });
});
