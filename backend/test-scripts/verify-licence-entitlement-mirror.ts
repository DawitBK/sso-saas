/**
 * verify-licence-entitlement-mirror.ts: live checks of per-application licensing (docs/operations/PLATFORM-LICENSING.md section 9) against the RUNNING
 * production-parity mirror: real SSO signing with the dedicated key, real GMS and DMS processes polling it.
 *
 *   I_UNDERSTAND_THIS_CHANGES_MIRROR_LICENCES=idpprod node scripts/run-with-env.cjs mirror npx tsx test-scripts/verify-licence-entitlement-mirror.ts
 *
 * Needs the mirror up with LICENSE_POLL_SECONDS=15 in the GMS and DMS .env.mirror (the test removes and restores the mirror's licence rows, so run it
 * only against the mirror). It observes the gate without logging in: an unauthenticated request to a protected path answers 401 while licensed and
 * 403 LICENSE_REQUIRED while unlicensed (the gate runs before authentication). Prints PASS or FAIL per check and never a token or a secret.
 */
import crypto from 'node:crypto';
import { SignJWT, exportJWK, calculateJwkThumbprint } from 'jose';
import { pool } from '../src/db/pool.js';
import { IDP_CONFIG } from '../src/config.js';
import { findLicense, highestVersionEver, insertEvent, insertLicense } from '../src/licenses/repository.js';
import { validateLicenseInput } from '../src/licenses/validation.js';
import { nextLicenseVersion } from '../src/licenses/version.js';

const confirm = process.env.I_UNDERSTAND_THIS_CHANGES_MIRROR_LICENCES;
const { rows: dbRows } = await pool.query<{ db: string }>('SELECT current_database() AS db');
if (confirm !== dbRows[0].db || !IDP_CONFIG.licenseRequired) {
  console.error(`Refusing: set I_UNDERSTAND_THIS_CHANGES_MIRROR_LICENCES=${dbRows[0].db} and run it with the mirror env (LICENSE_REQUIRED must be true).`);
  process.exit(2);
}

const SSO = 'http://127.0.0.1:9300';
const SYSTEMS = {
  gms: { base: 'http://127.0.0.1:9200', protectedPath: '/api/v1/users', install: '/api/v1/license/install' },
  dms: { base: 'http://127.0.0.1:9100', protectedPath: '/api/v1/documents', install: '/api/v1/license/install' },
} as const;
type Sys = keyof typeof SYSTEMS;

let failures = 0;
const check = (name: string, ok: boolean, detail = ''): void => {
  if (!ok) failures += 1;
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function probe(sys: Sys): Promise<{ status: number; code: string | null }> {
  try {
    const r = await fetch(`${SYSTEMS[sys].base}${SYSTEMS[sys].protectedPath}`, { signal: AbortSignal.timeout(15000) });
    const body = (await r.json().catch(() => ({}))) as { error?: { code?: string } };
    return { status: r.status, code: body?.error?.code ?? null };
  } catch {
    return { status: 0, code: null };
  }
}
const isLicensed = async (sys: Sys) => {
  const p = await probe(sys);
  return p.status !== 0 && !(p.status === 403 && p.code === 'LICENSE_REQUIRED');
};
async function waitFor(cond: () => Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return true;
    await sleep(2500);
  }
  return cond();
}
const ssoToken = async (sys: Sys): Promise<string | null> => {
  const r = await fetch(`${SSO}/api/v1/licenses/public/${sys}`);
  return r.status === 200 ? (((await r.json()) as { token: string }).token) : null;
};
async function install(sys: Sys, token: string): Promise<{ status: number; code: string | null; outcome: string | null }> {
  const r = await fetch(`${SYSTEMS[sys].base}${SYSTEMS[sys].install}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }) });
  const body = (await r.json().catch(() => ({}))) as { data?: { outcome?: string }; outcome?: string; error?: { code?: string } };
  return { status: r.status, code: body?.error?.code ?? null, outcome: body?.data?.outcome ?? body?.outcome ?? null };
}
async function removeLicense(sys: string): Promise<void> {
  await pool.query('DELETE FROM licenses WHERE system = $1', [sys]);
}
async function restoreLicense(sys: 'sso' | Sys): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const checked = validateLicenseInput(sys, { customer: 'Example', expiresAt: null, modes: ['sso'] }, await findLicense(sys, client, true));
    if (!checked.ok) throw new Error('validation');
    const version = nextLicenseVersion(await highestVersionEver(sys, client), Date.now());
    const license = await insertLicense({ system: sys, ...checked.value, version, actor: 'mirror-test' }, client);
    await insertEvent({ system: sys, action: 'create', actor: 'mirror-test', version, before: null, after: license }, client);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

console.log('Per-application licensing on the mirror\n');

console.log('1. baseline: both systems are licensed and serving');
for (const sys of ['gms', 'dms'] as Sys[]) check(`${sys} is licensed`, await waitFor(() => isLicensed(sys), 60_000));
const keptGms = await ssoToken('gms');
const keptDms = await ssoToken('dms');
check('SSO serves a token for each', Boolean(keptGms && keptDms));

console.log('\n2. removing the licence in SSO makes a system that SSO had served unlicensed (within the poll), and restoring it brings it back');
for (const sys of ['gms', 'dms'] as Sys[]) {
  await removeLicense(sys);
  check(`${sys}: unlicensed after SSO answers 404`, await waitFor(async () => !(await isLicensed(sys)), 90_000));
  const p = await probe(sys);
  check(`${sys}: refusal is 403 LICENSE_REQUIRED`, p.status === 403 && p.code === 'LICENSE_REQUIRED', `${p.status} ${p.code}`);
  await restoreLicense(sys);
  check(`${sys}: licensed again after a higher version is issued`, await waitFor(() => isLicensed(sys), 90_000));
}

console.log('\n3. an OFFLINE-installed token survives SSO having no licence at all (the 404 must not kill it)');
for (const [sys, token] of [['gms', keptGms], ['dms', keptDms]] as Array<[Sys, string | null]>) {
  if (!token) { check(`${sys}: kept token available`, false); continue; }
  await removeLicense(sys);
  await waitFor(async () => !(await isLicensed(sys)), 90_000);
  const r = await install(sys, token);
  check(`${sys}: the (older) token installs`, r.status === 200, `${r.status} ${r.outcome ?? r.code}`);
  check(`${sys}: licensed after install`, await waitFor(() => isLicensed(sys), 20_000));
  await sleep(50_000); // three-plus polls with SSO answering 404 the whole time
  check(`${sys}: still licensed after several polls that got 404`, await isLicensed(sys));
  await restoreLicense(sys);
  await sleep(20_000);
  check(`${sys}: and still licensed once SSO serves the licence again`, await isLicensed(sys));
}

console.log('\n4. forged, garbage and wrong-system tokens are refused');
for (const sys of ['gms', 'dms'] as Sys[]) {
  const garbage = await install(sys, 'not.a.token');
  check(`${sys}: garbage is refused`, garbage.status === 400, `${garbage.status} ${garbage.code}`);
  const wrongKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const kid = await calculateJwkThumbprint(await exportJWK(wrongKey.publicKey));
  const forged = await new SignJWT({ sys, ver: 999, customer: 'Evil', expiresAt: null, graceDays: 14, warnDays: 30, maxUsers: null, modules: null, modes: ['sso', 'standalone'], jti: `${sys}-v999` })
    .setProtectedHeader({ alg: 'RS256', typ: 'kcms-license+jwt', kid })
    .setIssuer(IDP_CONFIG.issuer).setAudience(`license:${sys}`).setIssuedAt().sign(wrongKey.privateKey);
  const bad = await install(sys, forged);
  check(`${sys}: a token signed by an unknown key is refused`, bad.status === 400, `${bad.status} ${bad.code}`);
}
const other: Sys = 'dms';
const gmsToken = await ssoToken('gms');
if (gmsToken) {
  const r = await install(other, gmsToken);
  check('dms refuses a token issued for gms', r.status === 400, `${r.status} ${r.code}`);
}

console.log('\n5. SSO enforces its own requirement: no licence for SSO means nothing but sign-in, licences and health');
await removeLicense('sso');
const refused = await waitFor(async () => {
  const r = await fetch(`${SSO}/api/v1/admin/users`).catch(() => null);
  return r?.status === 403 && ((await r.json().catch(() => ({}))) as { error?: { code?: string } })?.error?.code === 'LICENSE_REQUIRED';
}, 30_000);
check('SSO admin API answers 403 LICENSE_REQUIRED without its licence', refused);
check('SSO still serves the public licence tokens (so GMS and DMS keep their licences)', (await fetch(`${SSO}/api/v1/licenses/public/gms`)).status === 200);
check('SSO health still answers', (await fetch(`${SSO}/health`)).status === 200);
await restoreLicense('sso');
const back = await waitFor(async () => {
  const r = await fetch(`${SSO}/api/v1/admin/users`).catch(() => null);
  return r !== null && r.status !== 403;
}, 30_000);
check('SSO is served again once its licence is back', back);

console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
await pool.end();
process.exit(failures === 0 ? 0 : 1);
