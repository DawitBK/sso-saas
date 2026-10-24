/**
 * Pins the module catalogue (src/licenses/catalog.ts) to section 7 of docs/operations/PLATFORM-LICENSING.md, the contract GMS and DMS keep
 * the same keys against. If the contract's list changes, this fails until the code follows (and the other two systems' pins fail too).
 */
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { LICENSE_SYSTEMS, MODULE_CATALOG, isLicenseSystem, moduleKeys } from '../src/licenses/catalog.js';

const DOC = path.resolve(__dirname, '../../docs/operations/PLATFORM-LICENSING.md');

/** The backtick-quoted keys in a section-7 bullet, up to its "Core:" part. */
function documentedKeys(markdown: string, system: 'GMS' | 'DMS'): string[] {
  const section = markdown.slice(markdown.indexOf('## 7. Module catalogue'));
  const start = section.indexOf(`- **${system}:**`);
  const bullet = section.slice(start).split(/\n- \*\*/)[0];
  const gateable = bullet.slice(0, bullet.indexOf('Core:'));
  return [...gateable.matchAll(/`([a-z_]+)`/g)].map((m) => m[1]);
}

describe('module catalogue', () => {
  const doc = existsSync(DOC) ? readFileSync(DOC, 'utf8') : null;

  (doc ? it : it.skip)('GMS keys equal the contract document', () => {
    expect(moduleKeys('gms')).toEqual(documentedKeys(doc!, 'GMS'));
  });

  (doc ? it : it.skip)('DMS keys equal the contract document', () => {
    expect(moduleKeys('dms')).toEqual(documentedKeys(doc!, 'DMS'));
  });

  it('SSO has nothing gateable', () => {
    expect(MODULE_CATALOG.sso).toEqual([]);
  });

  it('keys are unique per system, lower-case, and every entry has a label and a description', () => {
    for (const system of LICENSE_SYSTEMS) {
      const keys = moduleKeys(system);
      expect(new Set(keys).size).toBe(keys.length);
      for (const m of MODULE_CATALOG[system]) {
        expect(m.key).toMatch(/^[a-z_]+$/);
        expect(m.label.length).toBeGreaterThan(0);
        expect(m.description.length).toBeGreaterThan(0);
      }
    }
  });

  it('recognises exactly the three systems', () => {
    expect([...LICENSE_SYSTEMS]).toEqual(['sso', 'gms', 'dms']);
    expect(isLicenseSystem('gms')).toBe(true);
    expect(isLicenseSystem('mos')).toBe(false);
    expect(isLicenseSystem(undefined)).toBe(false);
  });
});
