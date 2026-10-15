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
const get = async (u, h = {}) => {
  const r = await fetch(u, { headers: { cookie: ck(), ...h }, redirect: 'manual' });
  store(r);
  return r;
};

let r = await get('http://localhost:7301/portal');
for (let i = 0; i < 8 && [301, 302, 303, 307, 308].includes(r.status); i++) {
  const l = r.headers.get('location');
  r = await get(l.startsWith('http') ? l : `http://localhost:7301${l}`);
}
const html = await r.text();
const uid = (html.match(/\/interaction\/([^/"]+)\/login/) || [])[1];
console.log('frontend_html_login_form', Boolean(uid));
console.log('frontend_content_type_looks_html', html.includes('<!DOCTYPE html>') || html.includes('<html'));

const bj = await get(`http://localhost:7300/interaction/${uid}`, {
  'x-sso-ui': '1',
  accept: 'application/vnd.sso.view+json',
});
const body = await bj.text();
console.log('backend_view_status', bj.status);
console.log('backend_view_ct', bj.headers.get('content-type'));
console.log('backend_view_body', body.slice(0, 280));
const parsed = JSON.parse(body);
console.log('backend_view_name', parsed.view);
console.log('RESULT', parsed.view === 'login' && uid ? 'PASS' : 'FAIL');
