// End-to-end OIDC Authorization-Code + PKCE flow driver against the local IdP.
// Verifies: login interaction, consent, code issuance, token exchange, id_token
// claims (email, email_verified, ad_groups) — the exact shape DMS consumes.
import crypto from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';

const ISSUER = 'http://localhost:7300';
const CLIENT_ID = 'edams';
const CLIENT_SECRET = 'edams-dev-secret';
const REDIRECT_URI = 'http://localhost:7101/auth/callback';

const jar = new Map();
function storeCookies(resp) {
  for (const c of resp.headers.getSetCookie?.() ?? []) {
    const [pair] = c.split(';');
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (val === '' ) jar.delete(name); else jar.set(name, val);
  }
}
function cookieHeader() { return [...jar].map(([k, v]) => `${k}=${v}`).join('; '); }

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
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// Follow provider redirects within the IdP, stopping when it redirects to REDIRECT_URI.
const isRedirect = (s) => [301, 302, 303, 307, 308].includes(s);
async function follow(resp) {
  let r = resp;
  for (let i = 0; i < 8; i++) {
    if (!isRedirect(r.status)) return r;
    const loc = r.headers.get('location');
    if (loc.startsWith(REDIRECT_URI)) return r;
    const next = loc.startsWith('http') ? loc : ISSUER + loc;
    r = await get(next);
  }
  return r;
}

function extractField(html, name) {
  const m = html.match(new RegExp(`name="${name}"[^>]*value="([^"]*)"`)) || html.match(new RegExp(`value="([^"]*)"[^>]*name="${name}"`));
  return m ? m[1] : null;
}
function extractUid(html) {
  const m = html.match(/\/interaction\/([^/"]+)\/login/) || html.match(/\/interaction\/([^/"]+)\/confirm/);
  return m ? m[1] : null;
}

async function main() {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  const state = b64url(crypto.randomBytes(8));
  const nonce = b64url(crypto.randomBytes(8));

  const authUrl = `${ISSUER}/authorize?` + new URLSearchParams({
    client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code',
    scope: 'openid profile email', state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256',
  });

  // 1) Start authorize → redirect to login interaction
  let r = await follow(await get(authUrl));
  let html = await r.text();
  let uid = extractUid(html);
  let csrf = extractField(html, 'csrf');
  console.log('1) login page uid=%s csrf=%s', uid, !!csrf);
  if (!uid || !csrf) throw new Error('login page not rendered:\n' + html.slice(0, 400));

  // 2) Submit credentials
  r = await postForm(`${ISSUER}/interaction/${uid}/login`, { csrf, email: 'admin@examplecorp.com', password: 'demo' });
  console.log('2) login POST ->', r.status, r.headers.get('location'));
  r = await follow(r);

  // 3) Consent page (if shown)
  if (r.status === 200) {
    html = await r.text();
    uid = extractUid(html);
    csrf = extractField(html, 'csrf');
    console.log('3) consent page uid=%s csrf=%s', uid, !!csrf);
    r = await follow(await postForm(`${ISSUER}/interaction/${uid}/confirm`, { csrf }));
  }

  // 4) Expect redirect to REDIRECT_URI with code
  console.log('4) final ->', r.status, r.headers.get('location'));
  const loc = r.headers.get('location') || '';
  const code = new URL(loc).searchParams.get('code');
  const gotState = new URL(loc).searchParams.get('state');
  if (!code) throw new Error('no code in redirect: ' + loc);
  if (gotState !== state) throw new Error('state mismatch');
  console.log('   got code, state OK');

  // 5) Exchange code for tokens
  const tok = await fetch(`${ISSUER}/token`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET, code_verifier: verifier,
    }).toString(),
  });
  const tokens = await tok.json();
  console.log('5) token ->', tok.status, 'keys:', Object.keys(tokens).join(','));
  if (!tokens.id_token) throw new Error('no id_token: ' + JSON.stringify(tokens));

  // 6) Verify id_token
  const JWKS = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
  const { payload } = await jwtVerify(tokens.id_token, JWKS, { issuer: ISSUER, audience: CLIENT_ID });
  console.log('6) id_token verified. claims:');
  console.log('   sub:', payload.sub);
  console.log('   email:', payload.email, '| email_verified:', payload.email_verified);
  console.log('   name:', payload.name);
  console.log('   ad_groups:', JSON.stringify(payload['https://edams.examplecorp.com/ad_groups']));
  console.log('   nonce matches:', payload.nonce === nonce);

  const ok = payload.email === 'admin@examplecorp.com'
    && payload.email_verified === true
    && Array.isArray(payload['https://edams.examplecorp.com/ad_groups'])
    && payload['https://edams.examplecorp.com/ad_groups'].length > 0
    && payload.nonce === nonce;
  console.log('\nRESULT:', ok ? 'PASS ✅' : 'FAIL ❌');
  if (!ok) process.exit(1);
}
main().catch((e) => { console.error('ERROR', e); process.exit(1); });
