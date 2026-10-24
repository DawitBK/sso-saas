// CI gate over `npm audit` for the dependencies that ship (production only).
//
// Fails on any HIGH or CRITICAL advisory unless it is listed in ACCEPTED below with a written reason and an expiry date. An accepted
// advisory stops being accepted on its expiry date, so it comes back for a decision instead of being forgotten; a listed advisory that
// no longer appears is reported so the entry can be deleted.
//
// Why a list and not `--audit-level`: a plain level gate turns red on an advisory that has NO fixed version published, and then gets
// switched off for everything. This keeps the gate on and makes each exception explicit and dated.
//
// Usage: node scripts/audit-gate.mjs   (from backend; needs network access to the npm registry)
import { spawnSync } from 'node:child_process';

const ACCEPTED = [
  {
    ghsa: 'GHSA-vfj7-8cjw-p6xm',
    package: 'braces',
    until: '2027-01-31',
    reason:
      'Denial of service through deeply nested glob patterns. No fixed version exists (braces 3.0.3 is the latest). It is reached only through ' +
      'http-proxy-middleware -> micromatch, which SSO uses for the GMS gateway with fixed, code-defined paths; no request can supply a pattern. ' +
      'Revisit when braces publishes a fix or the gateway no longer needs http-proxy-middleware.',
  },
];

const res = spawnSync('npm', ['audit', '--omit=dev', '--json'], { encoding: 'utf8', shell: process.platform === 'win32', maxBuffer: 32 * 1024 * 1024 });
let report;
try {
  report = JSON.parse(res.stdout);
} catch {
  console.error('Could not read npm audit output (is the registry reachable?).\n' + (res.stderr ?? ''));
  process.exit(2);
}

const today = new Date().toISOString().slice(0, 10);
const advisories = new Map(); // ghsa -> { severity, packages:Set }
for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
  for (const via of v.via ?? []) {
    if (typeof via !== 'object') continue;
    const id = (via.url ?? '').split('/').pop();
    if (!id) continue;
    const entry = advisories.get(id) ?? { severity: via.severity, title: via.title, packages: new Set() };
    entry.packages.add(name);
    advisories.set(id, entry);
  }
}

let failed = false;
for (const [id, a] of advisories) {
  if (!['high', 'critical'].includes(a.severity)) continue;
  const accepted = ACCEPTED.find((x) => x.ghsa === id);
  if (accepted && accepted.until >= today) {
    console.log(`ACCEPTED  ${id} (${a.severity}) in ${accepted.package}, until ${accepted.until}`);
  } else {
    failed = true;
    console.error(`FAIL      ${id} (${a.severity}) ${a.title} [${[...a.packages].join(', ')}]${accepted ? `: the exception expired on ${accepted.until}` : ''}`);
  }
}
for (const x of ACCEPTED) if (!advisories.has(x.ghsa)) console.log(`NOTE      ${x.ghsa} no longer appears; delete its entry from ACCEPTED.`);

console.log(failed ? '\nAudit gate failed.' : '\nAudit gate passed.');
process.exit(failed ? 1 : 0);
