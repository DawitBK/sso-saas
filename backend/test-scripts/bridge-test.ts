// GMS bridge verification: mint a GMS-compatible session for an IdP identity,
// verify the HS256 token against GMS's JWT_SECRET, and confirm the provisioned
// rows in gmsdev (users, user_roles, auth_sessions). Proves the bypass.
import { jwtVerify } from 'jose';
import crypto from 'node:crypto';
import pg from 'pg';
import { IDP_CONFIG } from '../src/config.js';
import { mintGmsSession } from '../src/bridge/gms.js';

const identity = {
  email: 'admin@examplecorp.com',
  givenName: 'System',
  familyName: 'Administrator',
  groups: ['CN=EDAMS_Admins,OU=Groups,DC=examplecorp,DC=com'],
};

const session = await mintGmsSession(identity);
console.log('minted: userId=%s roles=%j office=%s session=%s', session.userId, session.roles, session.officeId, session.sessionId);

// 1) Verify the access token exactly as GMS's middleware does: jwt.verify(token, JWT_SECRET).
const secret = new TextEncoder().encode(IDP_CONFIG.gms.jwtSecret);
const { payload } = await jwtVerify(session.accessToken, secret);
console.log('access token verifies with GMS secret. payload:');
console.log('  id=%s (type %s) email=%s roles=%j office_id=%s session_id=%s',
  payload.id, typeof payload.id, payload.email, payload.roles, payload.office_id, payload.session_id);

// 2) Verify refresh token + auth_sessions row hash match GMS's scheme (sha256 hex).
const refreshHash = crypto.createHash('sha256').update(session.refreshToken).digest('hex');

const db = new pg.Pool({ connectionString: IDP_CONFIG.gms.databaseUrl });
const u = await db.query('SELECT id, email, status, email_verified FROM users WHERE id = $1', [session.userId]);
const roles = await db.query(
  `SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = $1 ORDER BY r.name`,
  [session.userId],
);
const sess = await db.query(
  'SELECT token_id, refresh_token_hash, expires_at FROM auth_sessions WHERE token_id = $1',
  [session.sessionId],
);
console.log('gmsdev.users:', u.rows[0]);
console.log('gmsdev.user_roles:', roles.rows.map((r) => r.name));
console.log('gmsdev.auth_sessions row present:', sess.rowCount === 1,
  '| hash matches refresh token:', sess.rows[0]?.refresh_token_hash === refreshHash);

const idIsNumeric = typeof payload.id === 'number' && Number.isFinite(payload.id);
const ok =
  idIsNumeric &&
  payload.email === identity.email &&
  Array.isArray(payload.roles) && payload.roles.includes('super_admin') &&
  typeof payload.session_id === 'string' &&
  u.rowCount === 1 &&
  roles.rows.some((r) => r.name === 'super_admin') &&
  sess.rowCount === 1 &&
  sess.rows[0].refresh_token_hash === refreshHash;

console.log('\nRESULT:', ok ? 'PASS ✅ (token accepted by GMS contract, user provisioned)' : 'FAIL ❌');
await db.end();
process.exit(ok ? 0 : 1);
