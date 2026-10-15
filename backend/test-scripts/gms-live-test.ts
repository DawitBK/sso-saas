// Live proof: mint a GMS session via the bridge, then call protected GMS APIs
// with the minted Bearer token against the RUNNING GMS backend (:7200).
import { mintGmsSession } from '../src/bridge/gms.js';
import { IDP_CONFIG } from '../src/config.js';

const GMS = IDP_CONFIG.gms.apiBase.replace(/\/$/, '');

const session = await mintGmsSession({
  email: 'admin@examplecorp.com',
  givenName: 'System',
  familyName: 'Administrator',
  groups: ['CN=EDAMS_Admins,OU=Groups,DC=examplecorp,DC=com'],
});
console.log('minted GMS token for userId=%s roles=%j', session.userId, session.roles);

async function call(pathname: string) {
  const r = await fetch(`${GMS}${pathname}`, {
    headers: { authorization: `Bearer ${session.accessToken}` },
  });
  const body = await r.text();
  console.log(`GET ${pathname} -> ${r.status}  ${body.slice(0, 160).replace(/\s+/g, ' ')}`);
  return r.status;
}

// /auth/me is behind requireAuth. A 200 proves GMS accepted the bridged token.
const meStatus = await call('/auth/me');
// Try an admin-scoped route too (super_admin should pass authorization).
await call('/offices');

console.log('\nRESULT:', meStatus === 200 ? 'PASS ✅ GMS accepted the bridged token (auth bypassed, no GMS changes)' : `CHECK (auth/me=${meStatus})`);
process.exit(meStatus === 200 ? 0 : 1);
