// Live login against the RUNNING IdP through the real interaction flow.
// Usage: node test-scripts/live-login.mjs [email] [password]
// Defaults to the SSO browser entry point on 7301 (frontend proxy).
const IDP = (process.env.SSO_FRONTEND_URL ?? process.env.IDP_ISSUER ?? 'http://localhost:7301').replace(/\/$/, '');
const jar = new Map();
const store = (r) => { for (const c of r.headers.getSetCookie?.() ?? []) { const [p] = c.split(';'); const i = p.indexOf('='); const n = p.slice(0, i).trim(), v = p.slice(i + 1).trim(); v ? jar.set(n, v) : jar.delete(n); } };
const ck = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
const isR = (s) => [301, 302, 303, 307, 308].includes(s);
const get = async (u) => { const r = await fetch(u, { headers: { cookie: ck() }, redirect: 'manual' }); store(r); return r; };
const post = async (u, f) => { const r = await fetch(u, { method: 'POST', headers: { cookie: ck(), 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(f).toString(), redirect: 'manual' }); store(r); return r; };
async function follow(r) { for (let i = 0; i < 10; i++) { if (!isR(r.status)) return r; const l = r.headers.get('location'); r = await get(l.startsWith('http') ? l : IDP + l); } return r; }

const email = process.argv[2] || 'admin@examplecorp.com';
const pw = process.argv[3] || 'demo';

let r = await follow(await get(`${IDP}/portal`));
let html = await r.text();
const uid = (html.match(/\/interaction\/([^/"]+)\/login/) || [])[1];
const csrf = (html.match(/name="csrf"[^>]*value="([^"]*)"/) || [])[1];
console.log('login form reached:', !!uid, '| csrf:', !!csrf);
if (!uid) { console.log('NO LOGIN FORM. head:', html.slice(0, 200)); process.exit(1); }

r = await post(`${IDP}/interaction/${uid}/login`, { csrf, email, password: pw });
console.log(`POST login "${email}" / "${pw}" -> ${r.status} ${r.headers.get('location') || ''}`);
if (r.status === 401 || r.status === 403) {
  const b = await r.text();
  console.log('server message:', (b.match(/class="error">([^<]+)/) || [])[1] || '(none)');
  console.log('RESULT: FAIL — credentials rejected');
  process.exit(1);
}
r = await follow(r);
const body = await r.text().catch(() => '');
console.log('final status:', r.status, '| portal(Welcome) reached:', /Welcome/i.test(body));
console.log('RESULT:', /Welcome/i.test(body) ? 'PASS ✅ running IdP accepts these credentials' : 'CHECK');
