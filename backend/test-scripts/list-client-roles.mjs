import dotenv from 'dotenv';
import pg from 'pg';

dotenv.config({ override: true });
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const { rows } = await pool.query(
  'SELECT client_id, role_name, office_scoped, sort_order FROM idp_client_roles ORDER BY client_id, sort_order',
);
for (const r of rows) {
  console.log(`${r.client_id}:${r.role_name}${r.office_scoped ? '(office)' : ''}`);
}
console.log(`total=${rows.length}`);
await pool.end();
