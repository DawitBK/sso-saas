/**
 * Mirrors real GMS/DMS users into the IdP as local accounts with EXAMPLE
 * cross-system role/permission assignments, so the admin console (and its
 * DMS-permission panels) can be exercised against realistic-looking data
 * instead of the single seeded admin from seed-dev.ts.
 *
 * Sources (all read-only — never edited by this script):
 *  - `GMS/backend/src/seeders/data/legacy-users.json` — 234 real employee
 *    rows, each `[id, officeId, email, password_hash, full_name, location,
 *    department]` (see GMS's own 002-password-seeder.js for this shape).
 *    `password_hash` (a real bcrypt hash, GMS's own bcryptjs) is copied
 *    VERBATIM into `idp_users.password_hash` — `verifyPassword()`
 *    (auth/password.ts) recognizes the `$2a$`/`$2b$`/`$2y$` prefix and
 *    verifies via bcrypt instead of SSO's own scrypt format, so each person
 *    can sign into SSO with the exact password they already use for GMS.
 *    This script never sees or needs their plaintext. These 234 also get
 *    DMS role `EMPLOYEE` (a real, existing low-privilege DMS role — see
 *    DMS/backend/src/config/permissions.ts) in addition to GMS's own
 *    existing `host` role assignment, which is left exactly as it was.
 *  - GMS's 2 bootstrap accounts (master@gms.local / admin@gms.local), hardcoded
 *    below with GMS role `super_admin`.
 *  - `DMS 10/backend/scripts/seed-core.ts`'s `DEMO_USERS` — 13 demo accounts,
 *    hardcoded below (email + DMS role), mirrored from that file by hand.
 *
 * The GMS bootstrap and DMS demo accounts above are synthetic, not real
 * people, so they keep the FIXED dev password seed-dev.ts's admin account
 * already uses, with must_change_password = TRUE. Only the 234 real legacy
 * employees get their own real (bcrypt) hash and must_change_password =
 * FALSE — forcing a change would defeat the point of reusing a password
 * they already know.
 *
 * A couple of the DMS demo users also get an illustrative permission
 * override via DMS's internal API, purely to demonstrate that feature on
 * real-looking data — best-effort: if DMS isn't reachable (its own seed
 * hasn't been run, or DMS_INTERNAL_API_KEY isn't set), this script warns and
 * continues rather than failing the whole run.
 *
 * GUARD: refuses to run when IDP_CONFIG.isProd — this script now handles 234
 * real employee names/emails and must never touch a production database
 * (mirrors DMS's own backend/scripts/seed-reset.ts production guard).
 *
 * Run: npm run db:seed:users  (after db:seed:dev)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Request } from 'express';
import { pool } from './pool.js';
import { hashPassword } from '../auth/password.js';
import { IDP_CONFIG } from '../config.js';
import { applyAccess, personalGroupDn, liveDmsStatus } from '../admin/router.js';
import { putDmsUserOverrides, DmsInternalApiError } from '../admin/dms-internal-client.js';

const PASSWORD = 'demo'; // same fixed dev password seed-dev.ts already uses for admin@examplecorp.com
const ACTOR_EMAIL = 'seed-script@examplecorp.local';
// Matches legacy-users.json's real GMS password hashes — auth/password.ts's
// verifyPassword() recognizes this prefix and verifies via bcrypt.
const BCRYPT_HASH_RE = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LEGACY_USERS_PATH = path.join(
  __dirname,
  '..', '..', '..', '..', // src/db -> backend -> SSO -> Example Corp_Systems
  // Renamed 2026-07-25 (Platform Architecture Standardization Directive):
  // 'GMS RELEASE V3' -> 'GMS'. This path silently ENOENT'd (caught + warned
  // on below) from the rename until 2026-07-26, skipping all 234 legacy rows.
  'GMS', 'backend', 'src', 'seeders', 'data', 'legacy-users.json',
);

interface DemoUser { email: string; firstName: string; lastName: string; role: string }

/** Mirrored by hand from `DMS 10/backend/scripts/seed-core.ts`'s DEMO_USERS —
 *  email + DMS role only (dept/tenant assignment stays DMS's own concern). */
const DMS_DEMO_USERS: DemoUser[] = [
  { email: 'admin@edams.local', firstName: 'System', lastName: 'Admin', role: 'SYSTEM_ADMIN' },
  { email: 'manager@edams.local', firstName: 'Dept', lastName: 'Manager', role: 'DEPT_MANAGER' },
  { email: 'officer@edams.local', firstName: 'Records', lastName: 'Officer', role: 'RECORDS_OFFICER' },
  { email: 'approver@edams.local', firstName: 'Document', lastName: 'Approver', role: 'APPROVER' },
  { email: 'employee@edams.local', firstName: 'Staff', lastName: 'Employee', role: 'EMPLOYEE' },
  { email: 'auditor@edams.local', firstName: 'System', lastName: 'Auditor', role: 'AUDITOR' },
  { email: 'hr.manager@edams.local', firstName: 'HR', lastName: 'Manager', role: 'DEPT_MANAGER' },
  { email: 'proc.manager@edams.local', firstName: 'Procurement', lastName: 'Manager', role: 'DEPT_MANAGER' },
  { email: 'it.officer@edams.local', firstName: 'IT', lastName: 'Officer', role: 'RECORDS_OFFICER' },
  { email: 'legal.approver@edams.local', firstName: 'Legal', lastName: 'Approver', role: 'APPROVER' },
  { email: 'ops.employee@edams.local', firstName: 'Ops', lastName: 'Staff', role: 'EMPLOYEE' },
  { email: 'exec.manager@edams.local', firstName: 'Executive', lastName: 'Manager', role: 'DEPT_MANAGER' },
  { email: 'chief@edams.local', firstName: 'Chief', lastName: 'Executive', role: 'EXECUTIVE' },
];

/** GMS's 2 bootstrap accounts — org-wide super_admin, no office required. */
const GMS_BOOTSTRAP_USERS: { email: string; givenName: string; familyName: string }[] = [
  { email: 'master@gms.local', givenName: 'GMS', familyName: 'Master' },
  { email: 'admin@gms.local', givenName: 'GMS', familyName: 'Admin' },
];

/** A couple of illustrative per-user permission overrides layered on top of
 *  the DMS demo users' role defaults — purely to demonstrate the feature,
 *  not applied to all 13 (let alone all 234 legacy users). */
const ILLUSTRATIVE_OVERRIDES: { email: string; grants: string[]; revokes: string[] }[] = [
  // RECORDS_OFFICER doesn't include role:manage by default — grant it to one
  // records officer as an example of widening a user beyond their role.
  { email: 'officer@edams.local', grants: ['role:manage'], revokes: [] },
  // DEPT_MANAGER includes department:manage by default — revoke it from one
  // manager as an example of narrowing a user below their role.
  { email: 'manager@edams.local', grants: [], revokes: ['department:manage'] },
];

/** Minimal stand-in for Express's Request — applyAccess only reads req.ip and
 *  req.get(...) (via writeAudit) on its DMS-role-mapping failure path; there
 *  is no real HTTP request in a seed script. */
function fakeReq(): Request {
  return { ip: undefined, get: () => undefined } as unknown as Request;
}

async function upsertIdpUser(
  email: string,
  givenName: string,
  familyName: string,
  passwordHash: string,
  mustChangePassword = true,
): Promise<string> {
  const { rows } = await pool.query<{ id: string }>(
    `INSERT INTO idp_users (email, email_verified, given_name, family_name, password_hash, source, is_active, must_change_password)
     VALUES ($1, TRUE, $2, $3, $4, 'local', TRUE, $5)
     ON CONFLICT (email) DO UPDATE SET
       given_name = EXCLUDED.given_name,
       family_name = EXCLUDED.family_name,
       password_hash = EXCLUDED.password_hash,
       must_change_password = EXCLUDED.must_change_password
     RETURNING id`,
    [email, givenName, familyName, passwordHash, mustChangePassword],
  );
  return rows[0].id;
}

async function assign(userId: string, email: string, dmsRole: string, gmsRole: string): Promise<void> {
  if (!dmsRole && !gmsRole) return;
  // officeId is always null here: none of the three source lists carry a
  // GMS office assignment per person, so office-scoped GMS roles (admin/
  // reception/host) are seeded WITHOUT an office. That's fine for exercising
  // the admin console's own UI against realistic names/roles, but a real SSO
  // login by one of these accounts would still be rejected by GMS pending an
  // office pick on that user's own page (see GMS_OFFICE_SCOPED_ROLES).
  await applyAccess(userId, email, personalGroupDn(userId), dmsRole, gmsRole, null, ACTOR_EMAIL, fakeReq());
}

function splitName(fullName: string): { givenName: string; familyName: string } {
  const parts = fullName.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return { givenName: '', familyName: '' };
  return { givenName: parts[0], familyName: parts.slice(1).join(' ') };
}

async function seedIllustrativeOverrides(): Promise<void> {
  for (const ex of ILLUSTRATIVE_OVERRIDES) {
    try {
      const live = await liveDmsStatus(ex.email);
      if (!live.exists || !live.id) {
        console.warn(`[seed-users] Skipping illustrative permission override for ${ex.email} — not found in DMS yet (run DMS's own seed-core first).`);
        continue;
      }
      await putDmsUserOverrides(IDP_CONFIG.dmsDefaultTenant, live.id, ex.grants, ex.revokes, ACTOR_EMAIL);
      console.log(`[seed-users] Illustrative override for ${ex.email}: +[${ex.grants.join(', ')}] -[${ex.revokes.join(', ')}]`);
    } catch (err) {
      const message = err instanceof DmsInternalApiError ? err.message : (err as Error).message;
      console.warn(`[seed-users] Could not seed illustrative permission override for ${ex.email}: ${message}`);
    }
  }
}

async function main(): Promise<void> {
  if (IDP_CONFIG.isProd) {
    throw new Error(
      'Refusing to run seed-users in production (IDP_CONFIG.isProd) — this seeds 234 real employee names/emails as local dev accounts.',
    );
  }

  const passwordHash = await hashPassword(PASSWORD);

  // 1. GMS bootstrap accounts (super_admin, org-wide).
  for (const u of GMS_BOOTSTRAP_USERS) {
    const userId = await upsertIdpUser(u.email, u.givenName, u.familyName, passwordHash);
    await assign(userId, u.email, '', 'super_admin');
  }
  console.log(`[seed-users] Seeded ${GMS_BOOTSTRAP_USERS.length} GMS bootstrap accounts.`);

  // 2. DMS demo users (DMS role only).
  for (const u of DMS_DEMO_USERS) {
    const userId = await upsertIdpUser(u.email, u.firstName, u.lastName, passwordHash);
    await assign(userId, u.email, u.role, '');
  }
  console.log(`[seed-users] Seeded ${DMS_DEMO_USERS.length} DMS demo accounts.`);

  // 3. Legacy GMS users (234) — host role only, per GMS's own seeding.
  let legacyRows: unknown[][] = [];
  try {
    legacyRows = JSON.parse(fs.readFileSync(LEGACY_USERS_PATH, 'utf8'));
  } catch (err) {
    console.warn(`[seed-users] Could not read legacy-users.json at ${LEGACY_USERS_PATH} — skipping the 234 legacy GMS users. (${(err as Error).message})`);
  }

  let legacyCount = 0;
  let legacySkippedNoHash = 0;
  for (const row of legacyRows) {
    const email = String(row[2] ?? '').trim().toLowerCase();
    const realHash = String(row[3] ?? '').trim();
    const fullName = String(row[4] ?? '').trim();
    if (!email) continue;
    if (!BCRYPT_HASH_RE.test(realHash)) {
      console.warn(`[seed-users] Skipping ${email} — legacy-users.json row has no valid bcrypt hash.`);
      legacySkippedNoHash++;
      continue;
    }
    const { givenName, familyName } = splitName(fullName || email.split('@')[0]);
    const userId = await upsertIdpUser(email, givenName, familyName, realHash, false);
    await assign(userId, email, 'EMPLOYEE', 'host');
    legacyCount++;
  }
  console.log(`[seed-users] Seeded ${legacyCount} legacy GMS users (their own real GMS password, host + EMPLOYEE roles)${legacySkippedNoHash ? `, skipped ${legacySkippedNoHash} with no valid hash` : ''}.`);

  // 4. A couple of illustrative DMS permission overrides (best-effort).
  await seedIllustrativeOverrides();

  console.log('[seed-users] Done.');
  // Importing router.ts pulls in the admin/internal-client graph, and some of
  // those dependencies still keep open handles longer than this script needs.
  // Force-exit once all awaited work is complete, mirroring the same open-
  // handle pattern documented for DMS's own tsx seed scripts.
  await pool.end().catch(() => {});
  process.exit(0);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
