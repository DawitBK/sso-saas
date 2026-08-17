/** Assert /admin/users/new exposes super_host from the client-scoped catalog. */
const IDP = (process.env.SSO_FRONTEND_URL ?? 'http://localhost:7301').replace(/\/$/, '');
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

let r = await follow(await get(`${IDP}/portal`));
let html = await r.text();
const uid = (html.match(/\/interaction\/([^/"]+)\/login/) || [])[1];
const csrf = (html.match(/name="csrf"[^>]*value="([^"]*)"/) || [])[1];
if (!uid) {
  console.log('FAIL: no login form');
  process.exit(1);
}
r = await follow(await post(`${IDP}/interaction/${uid}/login`, {
  csrf,
  email: 'admin@examplecorp.com',
  password: 'demo',
}));
r = await follow(await get(`${IDP}/admin/users/new`));
html = await r.text();
const gmsBlock = (html.match(/name="gms_role"[\s\S]*?<\/select>/) || [''])[0];
const values = [...gmsBlock.matchAll(/<option[^>]*value="([^"]*)"/g)].map((m) => m[1]).filter(Boolean);
console.log('gms_role options:', values.join(', ') || '(none)');
const required = ['super_admin', 'admin', 'super_reception', 'reception', 'super_host', 'host'];
const missing = required.filter((role) => !values.includes(role));
if (missing.length) {
  console.log('FAIL: missing roles:', missing.join(', '));
  process.exit(1);
}
console.log('RESULT: PASS — all six GMS staff roles present including super_host');
