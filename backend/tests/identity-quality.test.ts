import { dominantDomains, findIdentityProblems, type Identity } from '../scripts/lib/identityQuality.js';

const person = (email: string, given = 'Given', family = 'Family', active = true): Identity => ({ email, givenName: given, familyName: family, active, source: 'local' });
// twelve good addresses make acme.org the company domain (not example.com: that is on the junk list)
const COMPANY = Array.from({ length: 12 }, (_, i) => person(`staff${i}@acme.org`, `Staff${i}`, `Person${i}`));

describe('identity quality findings', () => {
  it('knows which domain carries the company', () => {
    expect(dominantDomains([...COMPANY, person('x@other.org')])).toEqual(['acme.org']);
  });

  it('reports a mistyped company domain with the suggested correction, and does not touch correct ones', () => {
    const f = findIdentityProblems([...COMPANY, person('abebe@acmee.org', 'Abebe', 'Kebede'), person('hana@acme.org', 'Hana', 'Tsegaye')]);
    expect(f).toEqual([{ kind: 'domain-typo', email: 'abebe@acmee.org', detail: expect.stringContaining('acme.org'), suggestion: 'abebe@acme.org' }]);
  });

  it('reports a domain with no dot and suggests the company domain when it is obviously that', () => {
    const f = findIdentityProblems([...COMPANY, person('daniel@acmeorg', 'Daniel', 'Alemu')]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ kind: 'no-domain-dot', suggestion: 'daniel@acme.org' });
  });

  it('flags throw-away addresses and empty names but suggests nothing', () => {
    const f = findIdentityProblems([...COMPANY, person('a@a.com', 'Ann', 'Lee'), person('someone@acme.org', '', 'Only')]);
    expect(f.map((x) => x.kind).sort()).toEqual(['junk-address', 'missing-name']);
    expect(f.every((x) => x.suggestion === null)).toBe(true);
  });

  it('flags two active accounts with one name, but not a disabled twin', () => {
    const twins = findIdentityProblems([...COMPANY, person('sara1@acme.org', 'Sara', 'Mekonnen'), person('sara2@acme.org', 'Sara', 'Mekonnen')]);
    expect(twins.filter((x) => x.kind === 'possible-duplicate')).toHaveLength(2);
    const oneDisabled = findIdentityProblems([...COMPANY, person('sara1@acme.org', 'Sara', 'Mekonnen'), person('sara2@acme.org', 'Sara', 'Mekonnen', false)]);
    expect(oneDisabled).toEqual([]);
  });

  it('is quiet for a clean directory', () => {
    expect(findIdentityProblems(COMPANY)).toEqual([]);
  });
});
