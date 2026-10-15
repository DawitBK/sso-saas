/**
 * Proves, against the RUNNING SSO (dev, port 7300), that a change made in the console's Clients page reaches oidc-provider on the
 * next request with no restart: oidc-provider itself is asked to authorize, before and after each change.
 *
 *   1. an address that is not registered is refused;
 *   2. register it (the same function the console calls), and the very next /authorize accepts it;
 *   3. restore the configured addresses, and it is refused again;
 *   4. switch the client off, and /authorize refuses the client altogether; switch it on, and it works again.
 *
 * It edits the dev `edams` client and always puts it back, even when a check fails. Dev only.
 *   npx tsx test-scripts/verify-client-live.ts
 */
import crypto from 'node:crypto';
import { pool } from '../src/db/pool.js';
import { IDP_CONFIG } from '../src/config.js';
import { setClientActive, updateClientUris } from '../src/oidc/client-admin.js';

if (IDP_CONFIG.isProd) { console.error('Refusing: dev only.'); process.exit(2); }
const ISSUER = process.env.SSO_LIVE_URL ?? 'http://localhost:7300';
const CLIENT = 'edams';
const NEW_URI = 'http://localhost:7101/auth/callback-live-check';

let failures = 0;
const check = (name: string, ok: boolean, detail = '') => { console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  -  ${detail}`}`); if (!ok) failures += 1; };

async function authorize(redirectUri: string): Promise<{ status: number; location: string; body: string }> {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const url = `${ISSUER}/authorize?${new URLSearchParams({
    client_id: CLIENT, response_type: 'code', redirect_uri: redirectUri, scope: 'openid', state: 'live', code_challenge: challenge, code_challenge_method: 'S256',
  })}`;
  const res = await fetch(url, { redirect: 'manual' });
  return { status: res.status, location: res.headers.get('location') ?? '', body: res.status >= 400 ? await res.text() : '' };
}
const accepted = (r: { status: number; location: string }) => r.status >= 300 && r.status < 400 && /interaction|authorize/.test(r.location);

const original = (await pool.query('SELECT redirect_uris, post_logout_redirect_uris, is_active FROM idp_clients WHERE client_id = $1', [CLIENT])).rows[0];
if (!original) { console.error(`client ${CLIENT} is not in the dev database`); process.exit(2); }
const seed = IDP_CONFIG.clientSeed.find((c) => c.client_id === CLIENT)!;

try {
  const registered = original.redirect_uris[0] as string;
  check('the registered address is accepted (baseline)', accepted(await authorize(registered)), 'baseline authorize failed; is SSO running on 7300?');

  const before = await authorize(NEW_URI);
  check('an address that is not registered is refused', !accepted(before) && before.status >= 400, `${before.status} ${before.location}`);

  await updateClientUris(CLIENT, { redirect: [...original.redirect_uris, NEW_URI], logout: original.post_logout_redirect_uris }, 'script:verify-client-live');
  check('the new address is accepted by the very next request, with no restart', accepted(await authorize(NEW_URI)));

  await updateClientUris(CLIENT, { redirect: seed.redirect_uris, logout: seed.post_logout_redirect_uris ?? [] }, 'script:verify-client-live');
  const afterRestore = await authorize(NEW_URI);
  check('after restoring the configured addresses it is refused again', !accepted(afterRestore) && afterRestore.status >= 400);

  await setClientActive(CLIENT, false, 'script:verify-client-live');
  const off = await authorize(registered);
  check('a client switched off is refused altogether', !accepted(off) && off.status >= 400, `${off.status} ${off.location}`);
  await setClientActive(CLIENT, true, 'script:verify-client-live');
  check('and works again when switched back on', accepted(await authorize(registered)));
} finally {
  await pool.query('UPDATE idp_clients SET redirect_uris = $2, post_logout_redirect_uris = $3, is_active = $4, updated_at = NOW() WHERE client_id = $1', [
    CLIENT, original.redirect_uris, original.post_logout_redirect_uris, original.is_active,
  ]);
  await pool.end().catch(() => undefined);
}
console.log(failures === 0 ? '\nAll client-management checks passed against the live SSO.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
