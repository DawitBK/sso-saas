// Full DMS SSO test: DMS authorize -> IdP login/consent -> code -> DMS callback.
// Proves DMS accepts an IdP-issued identity, provisions the user, and issues an
// EDAMS session. Requires IdP(:7300), DMS backend(:7100)+Redis running.
import { decodeJwt } from 'jose';

const DMS = 'http://localhost:7100/api/v1';
const IDP = 'http://localhost:7300';
const REDIRECT_URI = 'http://localhost:7101/auth/callback';

const jar = new Map();
function store(resp) {
  for (const c of resp.headers.getSetCookie?.() ?? []) {
    const [pair] = c.split(';'); const i = pair.indexOf('=');
    const n = pair.slice(0, i).trim(); const v = pair.slice(i + 1).trim();
    if (v === '') jar.delete(n); else jar.set(n, v);
  }
}
const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const isRedirect = (s) => [301, 302, 303, 307, 308].includes(s);
async function get(url) { const r = await fetch(url, { headers: { cookie: cookie() }, redirect: 'manual' }); store(r); return r; }
async function postForm(url, form) {
  const r = await fetch(url, { method: 'POST', headers: { cookie: cookie(), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form).toString(), redirect: 'manual' });
  store(r); return r;
}
// Follow redirects inside the IdP, stop at REDIRECT_URI.
async function follow(r) {
  for (let i = 0; i < 10; i++) {
    if (!isRedirect(r.status)) return r;
    const loc = r.headers.get('location');
    if (loc.startsWith(REDIRECT_URI)) return r;
    r = await get(loc.startsWith('http') ? loc : IDP + loc);
  }
  return r;
}
const field = (h, n) => (h.match(new RegExp(`name="${n}"[^>]*value="([^"]*)"`)) || [])[1];
const uidOf = (h) => (h.match(/\/interaction\/([^/"]+)\/(?:login|confirm)/) || [])[1];

async function main() {
  // 1) Kick off at DMS — it mints state/nonce (into Redis) and redirects to the IdP.
  let r = await get(`${DMS}/auth/oidc/authorize`);
  console.log('1) DMS authorize ->', r.status);
  if (!isRedirect(r.status)) throw new Error('DMS authorize did not redirect: ' + (await r.text()).slice(0, 200));
  const idpAuthUrl = r.headers.get('location');
  console.log('   -> IdP', idpAuthUrl.slice(0, 80) + '...');

  // 2) Enter IdP, render login
  r = await follow(await get(idpAuthUrl));
  let html = await r.text();
  let uid = uidOf(html); let csrf = field(html, 'csrf');
  console.log('2) IdP login page uid=%s', uid);
  if (!uid) throw new Error('no login page:\n' + html.slice(0, 300));

  // 3) Login
  r = await follow(await postForm(`${IDP}/interaction/${uid}/login`, { csrf, email: 'admin@examplecorp.com', password: 'demo' }));

  // 4) Consent if shown
  if (r.status === 200) {
    html = await r.text(); uid = uidOf(html); csrf = field(html, 'csrf');
    console.log('3) consent uid=%s', uid);
    r = await follow(await postForm(`${IDP}/interaction/${uid}/confirm`, { csrf }));
  }

  // 5) Code at redirect_uri
  const loc = r.headers.get('location') || '';
  const code = new URL(loc).searchParams.get('code');
  const state = new URL(loc).searchParams.get('state');
  console.log('4) code issued:', !!code, '| state:', !!state);
  if (!code) throw new Error('no code: ' + loc);

  // 6) Hand the code to DMS's callback (as the frontend page would).
  const cb = await fetch(`${DMS}/auth/callback`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, state }),
  });
  const data = await cb.json();
  console.log('5) DMS /auth/callback ->', cb.status);
  if (cb.status !== 200) throw new Error('callback failed: ' + JSON.stringify(data));

  const claims = data.accessToken ? decodeJwt(data.accessToken) : null;
  console.log('   user:', data.user?.email, '| roles:', JSON.stringify(data.user?.roles), '| tenant:', data.user?.tenantId);
  if (claims) console.log('   EDAMS token: iss=%s aud=%s user_id=%s perms=%d', claims.iss, claims.aud, claims.user_id, (claims.permissions || []).length);

  const ok = cb.status === 200 && !!data.accessToken && data.user?.email === 'admin@examplecorp.com';
  console.log('\nRESULT:', ok ? 'PASS ✅ DMS issued an EDAMS session from the IdP identity' : 'FAIL ❌');
  process.exit(ok ? 0 : 1);
}
main().catch((e) => { console.error('ERROR', e.message); process.exit(1); });
