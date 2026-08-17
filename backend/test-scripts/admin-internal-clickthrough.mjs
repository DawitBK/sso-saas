/**
 * Live SSO admin clickthrough proving internal DMS/GMS HTTP boundaries.
 *
 * Flow:
 *   1. Portal login through the 7301 frontend proxy
 *   2. Open /admin (requires admin group)
 *   3. /admin/users/new — must list GMS offices via GMS internal API (no officesError)
 *   4. /admin/dms-roles — must list DMS roles via DMS internal API
 *   5. Find admin user detail — must show live DMS/GMS status blocks without API errors
 *   6. Direct key probes — valid key 200, invalid key 401
 *
 * Usage: node test-scripts/admin-internal-clickthrough.mjs
 */
import dotenv from 'dotenv';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../.env'), override: true });

const IDP = (process.env.SSO_FRONTEND_URL ?? process.env.IDP_ISSUER ?? 'http://localhost:7301').replace(/\/$/, '');
const DMS = (process.env.DMS_API_BASE_URL ?? 'http://localhost:7100/api/v1').replace(/\/$/, '');
const GMS = (process.env.GMS_API_BASE ?? 'http://localhost:7200/api/v1').replace(/\/$/, '');
const DMS_KEY = process.env.DMS_INTERNAL_API_KEY ?? '';
const GMS_KEY = process.env.GMS_INTERNAL_API_KEY ?? '';
const TENANT = process.env.DMS_DEFAULT_TENANT ?? 'examplecorp';

const jar = new Map();
const store = (r) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const [p] = c.split(';');
    const i = p.indexOf('=');
    const n = p.slice(0, i).trim();
    const v = p.slice(i + 1).trim();
    if (v) jar.set(n, v);
    else jar.delete(n);
  }
};
const ck = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const isR = (s) => [301, 302, 303, 307, 308].includes(s);
const get = async (u) => {
  const r = await fetch(u, { headers: { cookie: ck() }, redirect: 'manual' });
  store(r);
  return r;
};
const post = async (u, f) => {
  const r = await fetch(u, {
    method: 'POST',
    headers: { cookie: ck(), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(f).toString(),
    redirect: 'manual',
  });
  store(r);
  return r;
};
async function follow(r) {
  for (let i = 0; i < 12; i++) {
    if (!isR(r.status)) return r;
    const l = r.headers.get('location');
    r = await get(l.startsWith('http') ? l : IDP + l);
  }
  return r;
}

const results = [];
function check(label, ok, detail = '') {
  results.push({ label, ok: !!ok });
  console.log(`   [${ok ? 'PASS' : 'FAIL'}] ${label}${detail ? ` — ${detail}` : ''}`);
}

const email = process.argv[2] || 'admin@examplecorp.com';
const pw = process.argv[3] || 'demo';

console.log(`SSO admin internal clickthrough via ${IDP}`);
console.log(`DMS=${DMS}  GMS=${GMS}  tenant=${TENANT}`);
console.log(`keys present: DMS=${Boolean(DMS_KEY)} GMS=${Boolean(GMS_KEY)}`);

// Direct internal probes first (independent of UI session)
{
  console.log('\n0) Direct internal API probes');
  if (!DMS_KEY || !GMS_KEY) {
    check('both internal API keys configured in SSO .env', false);
  } else {
    const dmsOk = await fetch(`${DMS}/internal/roles/tenants/${encodeURIComponent(TENANT)}/roles`, {
      headers: { 'x-internal-api-key': DMS_KEY },
    });
    check('DMS roles with valid key → 200', dmsOk.status === 200, `status=${dmsOk.status}`);
    const dmsBad = await fetch(`${DMS}/internal/roles/tenants/${encodeURIComponent(TENANT)}/roles`, {
      headers: { 'x-internal-api-key': 'definitely-not-the-real-key-xxxxxxxxxxxxxxxxxxxx' },
    });
    check('DMS roles with invalid key → 401', dmsBad.status === 401, `status=${dmsBad.status}`);

    const gmsOk = await fetch(`${GMS}/internal/sso/offices`, {
      headers: { 'x-internal-api-key': GMS_KEY, 'content-type': 'application/json' },
    });
    const gmsBody = await gmsOk.json().catch(() => null);
    const officeCount = Array.isArray(gmsBody?.data?.offices) ? gmsBody.data.offices.length : -1;
    check('GMS offices with valid key → 200', gmsOk.status === 200 && officeCount >= 0, `status=${gmsOk.status} offices=${officeCount}`);
    const gmsBad = await fetch(`${GMS}/internal/sso/offices`, {
      headers: { 'x-internal-api-key': 'definitely-not-the-real-key-xxxxxxxxxxxxxxxxxxxx', 'content-type': 'application/json' },
    });
    check('GMS offices with invalid key → 401', gmsBad.status === 401, `status=${gmsBad.status}`);

    const statusOk = await fetch(`${GMS}/internal/sso/users/by-email/${encodeURIComponent(email)}/status`, {
      headers: { 'x-internal-api-key': GMS_KEY, 'content-type': 'application/json' },
    });
    check('GMS user-status with valid key → 200', statusOk.status === 200, `status=${statusOk.status}`);
  }
}

// Portal login
console.log('\n1) Portal login through 7301');
let r = await follow(await get(`${IDP}/portal`));
let html = await r.text();
const uid = (html.match(/\/interaction\/([^/"]+)\/login/) || [])[1];
const csrf = (html.match(/name="csrf"[^>]*value="([^"]*)"/) || [])[1];
check('reached login form', Boolean(uid && csrf), `uid=${!!uid} csrf=${!!csrf}`);
if (!uid) {
  console.log('ABORT: no login form');
  process.exit(1);
}
r = await post(`${IDP}/interaction/${uid}/login`, { csrf, email, password: pw });
r = await follow(r);
html = await r.text();
check('portal Welcome after login', /Welcome/i.test(html), `status=${r.status}`);
check('portal shows Admin link', /href="\/admin"/i.test(html) || /Admin →/i.test(html));

// Admin dashboard
console.log('\n2) Admin dashboard');
r = await follow(await get(`${IDP}/admin`));
html = await r.text();
check('admin dashboard 200', r.status === 200 && /Dashboard/i.test(html), `status=${r.status}`);
check('not redirected to login / not 403', !r.url?.includes('/portal/login') && !/Admin access required/i.test(html));

// New-user page — GMS offices via internal API
console.log('\n3) /admin/users/new (GMS offices via internal API)');
r = await follow(await get(`${IDP}/admin/users/new`));
html = await r.text();
check('users/new 200', r.status === 200, `status=${r.status}`);
const officesError = /offices cannot be listed|Could not reach the GMS|GMS_INTERNAL_API_KEY is not configured|ERR-GMS/i.test(html);
check('no GMS offices error banner', !officesError);
const hasOfficeSelect = /name="office_id"/i.test(html) && /<option[^>]+value="\d+"/i.test(html);
check('office_id select populated with office options', hasOfficeSelect);

// DMS roles page
console.log('\n4) /admin/dms-roles (DMS roles via internal API)');
r = await follow(await get(`${IDP}/admin/dms-roles`));
html = await r.text();
check('dms-roles 200', r.status === 200, `status=${r.status}`);
const dmsRolesError = /Could not reach|DMS_INTERNAL_API_KEY|ERR-DMS|not configured/i.test(html);
check('no DMS roles error banner', !dmsRolesError);
check('dms-roles lists at least one role link', /\/admin\/dms-roles\/detail\?roleId=/i.test(html));

// User list → admin user detail (live status)
console.log('\n5) User detail live DMS/GMS status');
r = await follow(await get(`${IDP}/admin/users?q=${encodeURIComponent(email)}`));
html = await r.text();
const userHref = (html.match(new RegExp(`/admin/users/([0-9a-f-]{36})`, 'i')) || [])[0];
check('found user manage link for admin email', Boolean(userHref), userHref || 'none');
if (userHref) {
  r = await follow(await get(`${IDP}${userHref}`));
  html = await r.text();
  check('user detail 200', r.status === 200, `status=${r.status}`);
  const liveError = /GMS_INTERNAL_API_KEY is not configured|Could not reach the GMS|Could not reach DMS|DMS_INTERNAL_API_KEY is not configured/i.test(html);
  check('no live-status internal API error on user detail', !liveError);
  check('user detail shows System access / role controls', /System access|DMS role|GMS role/i.test(html));
}

const failed = results.filter((x) => !x.ok);
console.log(`\nRESULT: ${failed.length === 0 ? 'PASS' : 'FAIL'} — ${results.length - failed.length}/${results.length} checks passed`);
if (failed.length) {
  console.log('Failed:');
  for (const f of failed) console.log(`  - ${f.label}`);
  process.exit(1);
}
