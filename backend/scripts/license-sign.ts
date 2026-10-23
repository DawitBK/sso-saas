/**
 * license-sign.ts: sign a licence token OFFLINE (docs/operations/PLATFORM-LICENSING.md section 9.3).
 *
 *   npx tsx scripts/license-sign.ts --key <private.pem> --system gms --customer "Example Corp" --expires 2027-12-31 \
 *       [--version <n>] [--grace 14] [--warn 30] [--max-users 50] [--modules visits,ocr] [--modes sso,standalone] [--issuer urn:example:licence]
 *
 * Prints ONLY the token on stdout (everything else goes to stderr), so it can be piped or pasted into Admin > Licences or POSTed to a system's
 * /api/v1/license/install. The private key is read from the path you give and never leaves this process. Needs no database and no SSO.
 *
 * The licence version is the issue TIME (seconds since 2026-01-01 UTC; src/licenses/version.ts), the same rule the SSO console uses, so whichever
 * licence was issued last wins in every system, however it was issued. Do not pass --version: it is only a recovery tool, for example to beat a
 * version issued by a machine whose clock was set wrongly (a whole number from 1 to 2147483647, above the one to beat). Keep this PC's clock
 * correct. --expires is a date (end of that day, UTC), a full ISO date-time with a zone, or "never".
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { calculateJwkThumbprint, exportJWK, importPKCS8 } from 'jose';
import { isLicenseSystem } from '../src/licenses/catalog.js';
import { validateLicenseInput } from '../src/licenses/validation.js';
import { signLicenseTokenWith } from '../src/licenses/token.js';
import { LEGACY_VERSION_BELOW, isValidLicenseVersion, issueTimeOfVersion, versionFromTime } from '../src/licenses/version.js';
import type { LicenseRecord } from '../src/licenses/repository.js';

const args = process.argv.slice(2);
const arg = (name: string): string | undefined => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const fail = (message: string): never => {
  console.error(message);
  process.exit(2);
};

const keyPath = arg('key') ?? fail('Usage: license-sign.ts --key <private.pem> --system <sso|gms|dms> --customer <name> --expires <date|never> [--version <n>] [...]');
const system = arg('system');
if (!isLicenseSystem(system)) fail('--system must be sso, gms or dms.');
const issuedAtMs = Date.now();
const explicitVersion = arg('version');
if (explicitVersion === undefined && args.includes('--version')) fail('--version needs a value. Leave the option out to use the issue time.');
const version = explicitVersion === undefined ? versionFromTime(issuedAtMs) : Number(explicitVersion);
if (!isValidLicenseVersion(version)) fail('--version must be a whole number from 1 to 2147483647. Leave it out: the version is then the issue time, which is what you want.');
const expires = arg('expires') ?? fail('--expires is required: a date, a date-time with a zone, or "never".');

const body: Record<string, unknown> = { customer: arg('customer'), expiresAt: expires === 'never' ? null : expires };
if (arg('grace') !== undefined) body.graceDays = Number(arg('grace'));
if (arg('warn') !== undefined) body.warnDays = Number(arg('warn'));
if (arg('max-users') !== undefined) body.maxUsers = arg('max-users') === 'none' ? null : Number(arg('max-users'));
if (arg('modules') !== undefined) body.modules = arg('modules') === 'all' ? null : String(arg('modules')).split(',').filter(Boolean);
if (arg('modes') !== undefined) body.modes = String(arg('modes')).split(',').filter(Boolean);

const checked = validateLicenseInput(system as 'sso' | 'gms' | 'dms', body, null);
if (!checked.ok) fail(checked.details.map((d) => `${d.field}: ${d.message}`).join('\n'));
if (!checked.ok) process.exit(2);

const now = new Date(issuedAtMs).toISOString();
const record: LicenseRecord = { system: system as LicenseRecord['system'], ...checked.value, version, createdAt: now, updatedAt: now, updatedBy: 'offline' };

const pem = fs.readFileSync(keyPath, 'utf8');
const key = await importPKCS8(pem, 'RS256');
const kid = await calculateJwkThumbprint(await exportJWK(crypto.createPublicKey(pem)));
const token = await signLicenseTokenWith(record, key, kid, arg('issuer') ?? 'urn:examplecorp:license');

console.error(`Signed ${system} licence version ${version} for "${record.customer}", expires ${record.expiresAt ?? 'never'}, modes ${record.modes.join('+')}, kid ${kid.slice(0, 8)}.`);
const versionTime = issueTimeOfVersion(version);
if (explicitVersion === undefined) {
  console.error(`Version ${version} = issued ${now}. This replaces every ${system} licence issued before ${now}, however it was issued.`);
} else if (versionTime === null) {
  console.error(`Version ${version} was typed by hand and is an old-style number (below ${LEGACY_VERSION_BELOW}): a system that holds any licence issued by time will IGNORE it.`);
} else {
  const at = new Date(versionTime).toISOString();
  console.error(`Version ${version} was typed by hand and equals the issue time ${at}. This replaces every ${system} licence issued before ${at}.`);
  if (version < versionFromTime(issuedAtMs)) console.error(`Warning: that is earlier than now (${now}); a system already holding a licence issued after ${at} will ignore this one.`);
}
console.log(token);
