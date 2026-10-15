/**
 * identityQuality.ts: finds the accounts whose e-mail address or name looks wrong, as pure functions (tested in tests/identity-quality.test.ts).
 *
 * Most staff accounts were imported from GMS, where addresses were typed by hand: `...@kerchnshe.net`, `...@examplecorp.nets`, `...@examplecorpcom`, a stray `a@a.com`. An address is a
 * person's sign-in name and the key other systems use for them, so it is NEVER changed automatically: this module only reports, with the correction it would suggest, and a person
 * decides. (scripts/report-identity-quality.ts prints the report; scripts/one-time/verify-imported-users.ts holds the earlier hand-made list of the same kind.)
 */

export interface Identity {
  email: string;
  givenName: string;
  familyName: string;
  active: boolean;
  source: string;
}

export type FindingKind = 'no-domain-dot' | 'domain-typo' | 'junk-address' | 'missing-name' | 'possible-duplicate' | 'surrounding-space';

export interface Finding {
  kind: FindingKind;
  email: string;
  detail: string;
  /** What a person might change it to; always a suggestion, never applied. */
  suggestion: string | null;
}

function distance(a: string, b: string): number {
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length]!;
}

const JUNK_DOMAINS = [/^a\.com$/, /^example\./, /^test\./, /^company\.com$/, /(^|\.)mail\.bu\.app$/, /^mailinator\./, /^tempmail\./, /^yopmail\./];
const JUNK_LOCAL = /^(a|aa|asdf|test|testing|demo|temp|tmp|xxx|qwerty|abc)\d*$/i;

/** Domains that carry the company: at least `min` accounts use them. */
export function dominantDomains(all: Identity[], min = 10): string[] {
  const count = new Map<string, number>();
  for (const p of all) {
    const d = p.email.split('@')[1]?.toLowerCase();
    if (d) count.set(d, (count.get(d) ?? 0) + 1);
  }
  return [...count].filter(([, n]) => n >= min).map(([d]) => d);
}

export function findIdentityProblems(all: Identity[], opts: { dominantMin?: number } = {}): Finding[] {
  const findings: Finding[] = [];
  const dominant = dominantDomains(all, opts.dominantMin ?? 10);
  const seenNames = new Map<string, Identity[]>();
  for (const p of all) {
    const email = p.email;
    const [local = '', domain = ''] = email.split('@');
    if (email !== email.trim()) findings.push({ kind: 'surrounding-space', email, detail: 'The address has a space at its start or end', suggestion: email.trim() });
    const d = domain.toLowerCase();
    if (domain && !domain.includes('.')) {
      const near = dominant.find((x) => distance(d.replace(/(com|net|org)$/, '.$1'), x) <= 1 || distance(d, x.replace('.', '')) <= 1);
      findings.push({ kind: 'no-domain-dot', email, detail: `The domain "${domain}" has no dot`, suggestion: near ? `${local}@${near}` : null });
    } else if (domain && !dominant.includes(d)) {
      const near = dominant.map((x) => ({ x, n: distance(d, x) })).filter((c) => c.n <= 2).sort((a, b) => a.n - b.n)[0];
      if (near) findings.push({ kind: 'domain-typo', email, detail: `The domain "${domain}" is ${near.n} edit(s) from the company domain "${near.x}"`, suggestion: `${local}@${near.x}` });
    }
    if (JUNK_DOMAINS.some((r) => r.test(d)) || JUNK_LOCAL.test(local)) findings.push({ kind: 'junk-address', email, detail: 'Looks like a test or throw-away address', suggestion: null });
    if (!p.givenName.trim() || !p.familyName.trim()) findings.push({ kind: 'missing-name', email, detail: `${!p.givenName.trim() ? 'First' : 'Last'} name is empty`, suggestion: null });
    const nameKey = `${p.givenName} ${p.familyName}`.toLowerCase().replace(/\s+/g, ' ').trim();
    if (nameKey && p.givenName.trim() && p.familyName.trim()) seenNames.set(nameKey, [...(seenNames.get(nameKey) ?? []), p]);
  }
  for (const [name, people] of seenNames) {
    const active = people.filter((p) => p.active);
    if (active.length > 1) for (const p of active) findings.push({ kind: 'possible-duplicate', email: p.email, detail: `${active.length} active accounts are named "${name}": ${active.map((x) => x.email).join(', ')}`, suggestion: null });
  }
  return findings;
}
