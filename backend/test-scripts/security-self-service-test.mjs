// Self-service portal security features + the admin OIDC clients registry.
// Plain fetch + cookie-jar (no browser), same style as live-login.mjs /
// dms-sso-test.mjs. Requires the IdP running (`npm run dev`) and the dev seed
// applied (`npm run db:seed:dev` — admin@examplecorp.com / demo).
//
// Covers the three flows added on top of the existing admin/portal UI:
//   1. GET  /admin/clients                     — read-only OIDC client registry
//   2. POST /portal/security/password/change   — self-service password change
//   3. POST /portal/security/sessions/kill     — self-service session revocation
//
// IMPORTANT: step 2 changes admin@examplecorp.com's password to a temporary
// value and restores it to 'demo' before exiting (even on failure — see the
// `finally` block) so it never leaves the shared dev fixture broken for any
// other script or developer. If you ever see the "FAILED TO RESTORE" message
// below, sign in with the temp password printed there and set it back to
// 'demo' by hand (or use an admin password reset).

const IDP = 'http://localhost:7300';
const EMAIL = 'admin@examplecorp.com';
const ORIGINAL_PASSWORD = 'demo';
const TEMP_PASSWORD = 'qa-temp-Passw0rd-1!';

const isRedirect = (s) => [301, 302, 303, 307, 308].includes(s);
const field = (h, n) => (h.match(new RegExp(`name="${n}"[^>]*value="([^"]*)"`)) || [])[1];
const uidOf = (h) => (h.match(/\/interaction\/([^/"]+)\/login/) || [])[1];

/** Independent cookie-jar client — used both for the main session under test
 *  and for one-off "does this credential actually work" login probes that
 *  must not disturb the main session's cookies. */
function makeClient() {
  const jar = new Map();
  function store(resp) {
    for (const c of resp.headers.getSetCookie?.() ?? []) {
      const [pair] = c.split(';'); const i = pair.indexOf('=');
      const n = pair.slice(0, i).trim(); const v = pair.slice(i + 1).trim();
      if (v === '') jar.delete(n); else jar.set(n, v);
    }
  }
  const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  async function get(url) {
    const r = await fetch(url, { headers: { cookie: cookie() }, redirect: 'manual' });
    store(r); return r;
  }
  async function postForm(url, form) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form).toString(),
      redirect: 'manual',
    });
    store(r); return r;
  }
  async function follow(r) {
    for (let i = 0; i < 10; i++) {
      if (!isRedirect(r.status)) return r;
      const loc = r.headers.get('location');
      r = await get(loc.startsWith('http') ? loc : IDP + loc);
    }
    return r;
  }
  return { get, postForm, follow };
}

/** Full login through the real interaction flow. Returns whether the portal
 *  greeted the user afterward (the same signal live-login.mjs uses). */
async function login(client, email, password) {
  let r = await client.follow(await client.get(`${IDP}/portal`));
  let html = await r.text();
  const uid = uidOf(html);
  const csrf = field(html, 'csrf');
  if (!uid) return { ok: false, html, reason: 'no login form reached' };
  r = await client.follow(await client.postForm(`${IDP}/interaction/${uid}/login`, { csrf, email, password }));
  html = await r.text();
  return { ok: /Welcome/i.test(html), html };
}

function killForms(html) {
  const out = [];
  const re = /action="\/portal\/security\/sessions\/kill"[\s\S]*?name="kind" value="([^"]*)"[\s\S]*?name="key" value="([^"]*)"[\s\S]*?<\/form>/g;
  for (const m of html.matchAll(re)) out.push({ kind: m[1], key: m[2] });
  return out;
}

const results = [];
function check(label, cond) { results.push({ label, ok: !!cond }); console.log(`   [${cond ? 'PASS' : 'FAIL'}] ${label}`); }

async function main() {
  const main_ = makeClient();

  // ── 1) Log in as the seeded admin (source='local', in IDP_ADMIN_GROUP) ────
  console.log('1) log in as', EMAIL);
  const loggedIn = await login(main_, EMAIL, ORIGINAL_PASSWORD);
  check('logged in and reached the portal', loggedIn.ok);
  if (!loggedIn.ok) { throw new Error('cannot proceed without a session — aborting before touching anything'); }

  // ── 2) Admin: read-only OIDC clients registry ──────────────────────────────
  console.log('2) GET /admin/clients');
  let r = await main_.get(`${IDP}/admin/clients`);
  let html = await r.text();
  check('admin/clients loads for an admin-group member', r.status === 200);
  check('lists the seeded relying parties', /edams/i.test(html) && /gms/i.test(html) && /portal/i.test(html));
  check('never renders a client_secret value', !/client_secret/i.test(html));

  // ── 3) Portal security page: new sections present ──────────────────────────
  console.log('3) GET /portal/security');
  r = await main_.get(`${IDP}/portal/security`);
  html = await r.text();
  check('security page loads', r.status === 200);
  check('shows "Your active sessions"', html.includes('Your active sessions'));
  check('shows "Recent sign-in activity" with at least this run\'s sign-in', html.includes('Recent sign-in activity') && /Success/.test(html));
  const canChangePassword = html.includes('name="current_password"');
  check('password-change form shown for this local-source account', canChangePassword);

  // ── 4) Self-service password change: validation, then a real round-trip ────
  if (canChangePassword) {
    console.log('4) password change — validation + round-trip (restores "demo" at the end)');
    let csrf = field(html, 'csrf');

    r = await main_.postForm(`${IDP}/portal/security/password/change`, {
      csrf, current_password: 'definitely-wrong', new_password: TEMP_PASSWORD, confirm_password: TEMP_PASSWORD,
    });
    html = await r.text();
    check('wrong current password is rejected', r.status === 400 && html.includes('Current password is incorrect.'));

    csrf = field(html, 'csrf');
    r = await main_.postForm(`${IDP}/portal/security/password/change`, {
      csrf, current_password: ORIGINAL_PASSWORD, new_password: TEMP_PASSWORD, confirm_password: 'not-the-same',
    });
    html = await r.text();
    check('mismatched confirmation is rejected', r.status === 400 && html.includes('New passwords do not match.'));

    csrf = field(html, 'csrf');
    r = await main_.postForm(`${IDP}/portal/security/password/change`, {
      csrf, current_password: ORIGINAL_PASSWORD, new_password: 'short1', confirm_password: 'short1',
    });
    html = await r.text();
    check('too-short new password is rejected', r.status === 400 && html.includes('New password must be at least 8 characters.'));

    try {
      csrf = field(html, 'csrf');
      r = await main_.postForm(`${IDP}/portal/security/password/change`, {
        csrf, current_password: ORIGINAL_PASSWORD, new_password: TEMP_PASSWORD, confirm_password: TEMP_PASSWORD,
      });
      check('valid change is accepted (redirect)', isRedirect(r.status));
      r = await main_.follow(r);
      html = await r.text();

      const tempWorks = await login(makeClient(), EMAIL, TEMP_PASSWORD);
      check('the new password actually works for a fresh login', tempWorks.ok);
    } finally {
      // Always attempt to restore — this runs even if a check above threw.
      const restoreCsrf = field(html, 'csrf');
      const restore = await main_.postForm(`${IDP}/portal/security/password/change`, {
        csrf: restoreCsrf, current_password: TEMP_PASSWORD, new_password: ORIGINAL_PASSWORD, confirm_password: ORIGINAL_PASSWORD,
      }).catch(() => null);
      const restoredOk = Boolean(restore && isRedirect(restore.status));
      if (restoredOk) {
        console.log('   restored admin@examplecorp.com password back to "demo"');
      } else {
        const stillOriginal = await login(makeClient(), EMAIL, ORIGINAL_PASSWORD);
        if (stillOriginal.ok) {
          console.log('   password is already "demo" (temp change never landed) — nothing to restore');
        } else {
          console.error(`   !! FAILED TO RESTORE — sign in as ${EMAIL} with "${TEMP_PASSWORD}" and set the password back to "${ORIGINAL_PASSWORD}" manually.`);
        }
      }
      check('password restored to "demo" for other scripts/devs', restoredOk || (await login(makeClient(), EMAIL, ORIGINAL_PASSWORD)).ok);
    }
  } else {
    console.log('4) skipped — this account cannot self-service its password (unexpected for the dev seed)');
  }

  // ── 5) Self-service session revocation ──────────────────────────────────────
  console.log('5) session list + kill one of this run\'s own sessions');
  r = await main_.get(`${IDP}/portal/security`);
  html = await r.text();
  const before = killForms(html);
  check('at least one killable (non-current) session listed — this run\'s own SSO session', before.length > 0);

  if (before.length > 0) {
    const target = before[0];
    const csrf = field(html, 'csrf');
    r = await main_.postForm(`${IDP}/portal/security/sessions/kill`, { csrf, kind: target.kind, key: target.key });
    check('kill request redirects back to the security page', isRedirect(r.status));
    r = await main_.follow(r);
    html = await r.text();
    const after = killForms(html);
    const stillListed = after.some((s) => s.kind === target.kind && s.key === target.key);
    check(`killed session (${target.kind}) no longer listed`, !stillListed);
  } else {
    console.log('   (nothing to kill — skipping)');
  }

  const passed = results.filter((x) => x.ok).length;
  console.log(`\nRESULT: ${passed}/${results.length} checks passed.`);
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((err) => {
  console.error('ERROR', err.message);
  process.exit(1);
});
