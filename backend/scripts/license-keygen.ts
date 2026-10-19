/**
 * license-keygen.ts: make a licence-signing key pair (docs/operations/PLATFORM-LICENSING.md section 9.3).
 *
 *   npx tsx scripts/license-keygen.ts --out C:\Users\you\runtime\license-dev
 *
 * Writes the PRIVATE key (PKCS#8 PEM) into --out and prints only the PUBLIC half, ready for LICENSE_TRUST_PUBLIC_KEYS in GMS, DMS and SSO.
 * The private key is never printed. --out must be OUTSIDE this repository (a key inside a working tree ends up in a commit sooner or later).
 *
 * For development and the mirror this is fine to run anywhere. For PRODUCTION the owner runs it at a trusted terminal and keeps the private key off
 * every server (sign offline with license-sign.ts), and no agent should ever be given the output directory.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { calculateJwkThumbprint, exportJWK } from 'jose';

const args = process.argv.slice(2);
const out = args[args.indexOf('--out') + 1];
if (args.indexOf('--out') < 0 || !out) {
  console.error('Usage: license-keygen.ts --out <directory outside the repository>');
  process.exit(2);
}

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const outDir = path.resolve(out);
const rel = path.relative(repoRoot, outDir);
if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) {
  console.error(`Refusing: ${outDir} is inside the repository (${repoRoot}). Pick a folder outside it.`);
  process.exit(2);
}
fs.mkdirSync(outDir, { recursive: true });

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
const publicJwk = await exportJWK(publicKey);
const kid = await calculateJwkThumbprint(publicJwk);
const jwk = { ...publicJwk, kid, alg: 'RS256', use: 'sig' };
const privatePath = path.join(outDir, `license-private-${kid.slice(0, 8)}.pem`);
fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600, flag: 'wx' });
fs.writeFileSync(path.join(outDir, `license-public-${kid.slice(0, 8)}.jwk.json`), `${JSON.stringify(jwk, null, 2)}\n`);

// On Windows the mode above does nothing; restrict the file to the current user (best effort).
if (process.platform === 'win32') {
  const user = process.env.USERNAME;
  if (user) spawnSync('icacls', [privatePath, '/inheritance:r', '/grant:r', `${user}:(R,W)`], { stdio: 'ignore' });
}

console.log(`Private key written to ${privatePath} (never printed, never commit it).`);
console.log(`kid: ${kid}`);
console.log('\nPut this on every system that must trust licences signed with it (public key only):\n');
console.log(`LICENSE_TRUST_PUBLIC_KEYS=${JSON.stringify([jwk])}`);
console.log('\nPut this on the SSO that serves licence tokens online (optional; or sign offline with license-sign.ts):\n');
console.log(`LICENSE_SIGNING_KEY_FILE=${privatePath}`);
