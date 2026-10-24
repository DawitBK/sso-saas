/**
 * seed-qa-admin.ts — a throwaway SSO administrator for browser testing (dev only).
 *
 *   qa.ssoadmin@qa.local / Pass1234!      member of the admin group, no two-factor, not the platform administrator
 *   qa.hiddenowner@qa.local / Pass1234!   marked as a PLATFORM ADMINISTRATOR so the browser specs can prove it never
 *                                         appears in any list the other administrators see (dev database only)
 *
 * The Playwright specs in frontend/e2e sign in as this account (SSO_E2E_EMAIL / SSO_E2E_PASSWORD).
 * Refuses on production and on the production-parity mirror (IDP_CONFIG.isProd).
 */
import { pool } from '../src/db/pool.js';
import { IDP_CONFIG } from '../src/config.js';
import { hashPassword } from '../src/auth/password.js';

if (IDP_CONFIG.isProd) { console.error('Refusing: dev only.'); process.exit(2); }
const email = 'qa.ssoadmin@qa.local';
const hash = await hashPassword(process.env.QA_ADMIN_PASSWORD ?? 'Pass1234!');
const { rows } = await pool.query<{ id: string }>(
  `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, must_change_password)
   VALUES ($1, TRUE, 'QA', 'SSO Admin', $2, 'local', TRUE, FALSE)
   ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, must_change_password = FALSE, is_active = TRUE,
     failed_logins = 0, locked_until = NULL, updated_at = NOW()
   RETURNING id`,
  [email, hash],
);
await pool.query('INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING', [rows[0].id, IDP_CONFIG.adminGroup]);
const owner = await pool.query<{ id: string }>(
  `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, must_change_password)
   VALUES ('qa.hiddenowner@qa.local', TRUE, 'Hidden', 'Owner', $1, 'local', TRUE, FALSE)
   ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash RETURNING id`,
  [hash],
);
try {
  await pool.query('UPDATE idp_users SET is_platform_admin = TRUE WHERE id = $1', [owner.rows[0].id]);
  console.log('ready: qa.hiddenowner@qa.local (hidden platform administrator)');
} catch (e) {
  console.log('could not mark the hidden owner (the platform-admin guard refused):', (e as Error).message);
}
// Two plain local accounts with no groups and no side effects in DMS or GMS: the browser specs for the Users list's bulk actions
// disable, enable and sign out these two (and nobody real).
for (const n of ['qa.bulk1', 'qa.bulk2', 'qa.mfa']) {
  await pool.query(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, must_change_password)
     VALUES ($1, TRUE, 'QA', $2, $3, 'local', TRUE, FALSE)
     ON CONFLICT (email) DO UPDATE SET is_active = TRUE, updated_at = NOW()`,
    [`${n}@qa.local`, n, hash],
  );
}
console.log('ready: qa.bulk1@qa.local, qa.bulk2@qa.local (bulk-action specs), qa.mfa@qa.local (two-factor and recovery-code specs)');
console.log(`ready: ${email} (admin group ${IDP_CONFIG.adminGroup})`);
await pool.end().catch(() => {});
process.exit(0);
