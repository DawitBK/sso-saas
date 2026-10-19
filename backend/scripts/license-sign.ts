/**
 * license-sign.ts: sign a licence token OFFLINE (docs/operations/PLATFORM-LICENSING.md section 9.3).
 *
 *   npx tsx scripts/license-sign.ts --key <private.pem> --system gms --customer "Example Corp" --expires 2027-12-31 \
 *       --version 4 [--grace 14] [--warn 30] [--max-users 50] [--modules visits,ocr] [--modes sso,standalone] [--issuer urn:example:licence]
 *
 * Prints ONLY the token on stdout (everything else goes to stderr), so it can be piped or pasted into Admin > Licences or POSTed to a system's
 * /api/v1/license/install. The private key is read from the path you give and never leaves this process. Needs no database and no SSO.
 *
 * --version must be higher than the highest version already issued for that system (a system ignores a lower one); --expires is a date
 * (end of that day, UTC), a full ISO date-time with a zone, or "never".
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { calculateJwkThumbprint, exportJWK, importPKCS8 } from 'jose';
import { isLicenseSystem } from '../src/licenses/catalog.js';
import { validateLicenseInput } from '../src/licenses/validation.js';
import { signLicenseTokenWith } from '../src/licenses/token.js';
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

const keyPath = arg('key') ?? fail('Usage: license-sign.ts --key <private.pem> --system <sso|gms|dms> --customer <name> --expires <date|never> --version <n> [...]');
const system = arg('system');
if (!isLicenseSystem(system)) fail('--system must be sso, gms or dms.');
const version = Number(arg('version'));
if (!Number.isInteger(version) || version < 1) fail('--version must be a whole number of at least 1 (higher than any version already issued).');
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

const now = new Date().toISOString();
const record: LicenseRecord = { system: system as LicenseRecord['system'], ...checked.value, version, createdAt: now, updatedAt: now, updatedBy: 'offline' };

const pem = fs.readFileSync(keyPath, 'utf8');
const key = await importPKCS8(pem, 'RS256');
const kid = await calculateJwkThumbprint(await exportJWK(crypto.createPublicKey(pem)));
const token = await signLicenseTokenWith(record, key, kid, arg('issuer') ?? 'urn:examplecorp:license');

console.error(`Signed ${system} licence v${version} for "${record.customer}", expires ${record.expiresAt ?? 'never'}, modes ${record.modes.join('+')}, kid ${kid.slice(0, 8)}.`);
console.log(token);
