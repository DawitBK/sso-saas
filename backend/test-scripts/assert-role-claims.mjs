/**
 * Live-verify client-scoped role claims on the id_token (directive §6.3).
 * Runs the authorization-code flow through the public issuer (7301) and
 * exchanges at the backend token endpoint (7300) when needed.
 *
 * Expects admin@examplecorp.com / demo with EDAMS_Admins → GMS super_admin
 * and DMS SYSTEM_ADMIN mappings.
 */
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const PUBLIC = (process.env.IDP_ISSUER ?? 'http://localhost:7301').replace(/\/$/, '');
const INTERNAL = (process.env.IDP_INTERNAL_URL ?? 'http://localhost:7300').replace(/\/$/, '');
const CLIENT_ID = 'edams';
const CLIENT_SECRET = process.env.EDAMS_CLIENT_SECRET ?? 'edams-dev-secret';
const REDIRECT_URI = 'http://localhost:7101/auth/callback';
const GMS_ROLES_CLAIM = 'https://gms.examplecorp.com/roles';
const EDAMS_ROLES_CLAIM = 'https://edams.examplecorp.com/roles';
const AD_GROUPS_CLAIM = 'https://edams.examplecorp.com/ad_groups';

const jar = new Map();
function storeCookies(resp) {
  for (const c of resp.headers.getSetCookie?.() ?? []) {
    const [pair] = c.split(';');
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (val === '') jar.delete(name); else jar.set(name, val);
  }
}
function cookieHeader() { return [...jar].map(([k, v]) => `${k}=${v}`).join('; '); }
const isRedirect = (s) => [301, 302, 303, 307, 308].includes(s);
async function get(url) {
  const r = await fetch(url, { headers: { cookie: cookieHeader() }, redirect: 'manual' });
  storeCookies(r);
  return r;
}
async function postForm(url, form) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { cookie: cookieHeader(), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
    redirect: 'manual',
  });
  storeCookies(r);
  return r;
}
async function follow(resp) {
  let r = resp;
  for (let i = 0; i < 8; i++) {
    if (!isRedirect(r.status)) return r;
    const loc = r.headers.get('location');
    if (loc.startsWith(REDIRECT_URI)) return r;
    const next = loc.startsWith('http') ? loc : PUBLIC + loc;
    r = await get(next);
  }
  return r;
}
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function extractField(html, name) {
  const m = html.match(new RegExp(`name="${name}"[^>]*value="([^"]*)"`))
    || html.match(new RegExp(`value="([^"]*)"[^>]*name="${name}"`));
  return m ? m[1] : null;
}
function extractUid(html) {
  const m = html.match(/\/interaction\/([^/"]+)\/login/)
    || html.match(/\/interaction\/([^/"]+)\/confirm/);
  return m ? m[1] : null;
}

async function main() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(8));
  const nonce = b64url(crypto.randomBytes(8));

  const authUrl = `${PUBLIC}/authorize?` + new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code',
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256',
  });

  let r = await follow(await get(authUrl));
  let html = await r.text();
  let uid = extractUid(html);
  let csrf = extractField(html, 'csrf');
  if (!uid || !csrf) throw new Error('login page not rendered:\n' + html.slice(0, 400));

  r = await postForm(`${PUBLIC}/interaction/${uid}/login`, {
    csrf, email: 'admin@examplecorp.com', password: 'demo',
  });
  r = await follow(r);

  if (r.status === 200) {
    html = await r.text();
    uid = extractUid(html);
    csrf = extractField(html, 'csrf');
    r = await follow(await postForm(`${PUBLIC}/interaction/${uid}/confirm`, { csrf }));
  }

  const loc = r.headers.get('location') || '';
  const code = new URL(loc).searchParams.get('code');
  if (!code) throw new Error('no code in redirect: ' + loc);

  // Token exchange hits the backend directly (public issuer may not expose /token
  // differently — both 7301 proxy and 7300 work; prefer internal for stability).
  const tok = await fetch(`${INTERNAL}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: verifier,
    }).toString(),
  });
  const tokens = await tok.json();
  if (!tokens.id_token) throw new Error('no id_token: ' + JSON.stringify(tokens));

  const JWKS = createRemoteJWKSet(new URL(`${INTERNAL}/jwks`));
  const { payload } = await jwtVerify(tokens.id_token, JWKS, {
    issuer: PUBLIC,
    audience: CLIENT_ID,
  });

  const gmsRoles = payload[GMS_ROLES_CLAIM];
  const edamsRoles = payload[EDAMS_ROLES_CLAIM];
  const adGroups = payload[AD_GROUPS_CLAIM];

  console.log('email:', payload.email);
  console.log('ad_groups:', JSON.stringify(adGroups));
  console.log('gms_roles:', JSON.stringify(gmsRoles));
  console.log('edams_roles:', JSON.stringify(edamsRoles));

  const ok = payload.email === 'admin@examplecorp.com'
    && Array.isArray(adGroups) && adGroups.length > 0
    && Array.isArray(gmsRoles) && gmsRoles.includes('super_admin')
    && Array.isArray(edamsRoles) && edamsRoles.includes('SYSTEM_ADMIN')
    && payload.nonce === nonce;

  console.log('\nRESULT:', ok ? 'PASS' : 'FAIL');
  if (!ok) process.exit(1);
}

main().catch((e) => { console.error('ERROR', e); process.exit(1); });
