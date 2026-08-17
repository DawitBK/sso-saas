import { authenticateLocal } from '../src/auth/local-users.js';
import { verifyPassword } from '../src/auth/password.js';
import { pool } from '../src/db/pool.js';
const { rows } = await pool.query("SELECT email, password_hash FROM idp_users WHERE email='admin@examplecorp.com'");
console.log('row email:', JSON.stringify(rows[0]?.email));
console.log('hash:', rows[0]?.password_hash);
console.log('verify demo directly:', await verifyPassword('demo', rows[0]?.password_hash));
console.log('authenticateLocal(demo):', JSON.stringify(await authenticateLocal('admin@examplecorp.com','demo')));
await pool.end();
