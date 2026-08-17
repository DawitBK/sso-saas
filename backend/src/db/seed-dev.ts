/**
 * Dev seed: two local top-level accounts (admin@examplecorp.com,
 * master@examplecorp.com) + group membership, GMS role mapping, and app
 * entitlements, so the SSO flow and GMS bridge can be exercised without AD.
 *
 * GUARD: in production (IDP_CONFIG.isProd), refuses to run unless each
 * account's SEED_*_PASSWORD env var is set to something other than its fixed
 * dev default — both defaults are public in this repo's git history.
 *
 * Run: npm run db:seed:dev
 */

import { pool } from './pool.js';
import { hashPassword } from '../auth/password.js';
import { IDP_CONFIG } from '../config.js';


const ADMIN_GROUP = 'CN=EDAMS_Admins,OU=Groups,DC=examplecorp,DC=com';

// Both accounts land in ADMIN_GROUP, which already carries top-level access on
// both relying parties without any extra per-user wiring: GMS maps it to
// super_admin below, and DMS's own idp_role_mappings (seeded by
// db:seed:reference, relying_party='edams') maps it to SYSTEM_ADMIN.
const ACCOUNTS = [
  {
    email: process.env.SEED_ADMIN_EMAIL ?? 'admin@examplecorp.com',
    password: process.env.SEED_ADMIN_PASSWORD ?? 'demo',
    devDefaultPassword: 'demo',
    familyName: 'Administrator',
  },
  {
    // A second, distinct top-level account — mirrors the one manually seeded
    // directly on the live server during the 2026-08-02 infra audit
    // (SERVER-INFRASTRUCTURE-AUDIT.md §8), now made a permanent part of the
    // seed instead of a one-off live-box insert.
    email: process.env.SEED_MASTER_EMAIL ?? 'master@examplecorp.com',
    password: process.env.SEED_MASTER_PASSWORD ?? 'MasterTest#2026!',
    devDefaultPassword: 'MasterTest#2026!',
    familyName: 'Master',
  },
];

async function seedAccount(email: string, familyName: string, password: string): Promise<string> {
  const pwd = await hashPassword(password);
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active)
     VALUES ($1, TRUE, 'System', $2, $3, 'local', TRUE)
     ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, email_verified = TRUE
     RETURNING id`,
    [email, familyName, pwd],
  );
  const userId = rows[0].id;

  await pool.query(
    `INSERT INTO idp_user_groups (user_id, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
    [userId, ADMIN_GROUP],
  );

  return userId;
}

async function main(): Promise<void> {
  // The guard the header comment above already claimed existed, actually
  // implemented: each account's fixed dev-default password is public in this
  // repo's git history, so it must never reach a production idp_users row
  // regardless of who runs db:seed:dev:prod or with what intent.
  for (const { email, password, devDefaultPassword } of ACCOUNTS) {
    if (IDP_CONFIG.isProd && password === devDefaultPassword) {
      throw new Error(
        `Refusing to seed ${email} with its public dev default password in production — ` +
          `set the matching SEED_*_PASSWORD env var to a real password before running this against prod.`,
      );
    }
  }

  for (const { email, familyName, password } of ACCOUNTS) {
    const userId = await seedAccount(email, familyName, password);
    // eslint-disable-next-line no-console
    console.log(`Seeded local user ${email} / ${password} (id=${userId}) with group ${ADMIN_GROUP}`);
  }

  // GMS: EDAMS_Admins → super_admin (super role → no office_id required).
  await pool.query(
    `INSERT INTO idp_gms_role_mappings (group_dn, role_name) VALUES ($1, 'super_admin') ON CONFLICT DO NOTHING`,
    [ADMIN_GROUP],
  );

  // Portal entitlements (which apps this group may open) — group-level, so
  // shared by every account in ADMIN_GROUP.
  for (const rp of ['edams', 'gms', 'mrs']) {
    await pool.query(
      `INSERT INTO idp_app_entitlements (relying_party, group_dn) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [rp, ADMIN_GROUP],
    );
  }

  await pool.end();
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
