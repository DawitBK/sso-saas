/**
 * SSO (idp) database backup utility — Windows-native.
 *
 * PLATFORM_ARCHITECTURE.md §16 previously documented backup/recovery as
 * "a documentation fix only — no backup cron or script has been implemented
 * or scheduled on any production host." This is that script. SSO is the
 * platform's identity provider — every other system depends on it to log
 * anyone in, which makes an unprotected `idpprod` the single highest-impact
 * backup gap on the platform, worse than losing any one downstream system.
 *
 * Usage: npx tsx scripts/db-backup.ts [development|production]
 *
 * Restore gotcha (see /docs/operations/PLATFORM-OPERATIONS-GUIDE.md §1.2): session revocation
 * in SSO is row-deletion against live tables, not a separate log. Restoring
 * from a backup can silently resurrect a session that was revoked after the
 * backup was taken — cross-check idp_admin_audit for revocations in the gap
 * window after any restore.
 */
import { execSync } from "node:child_process";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { config as loadDotenv } from "dotenv";

// This package is "type": "module", so `__dirname` does not exist here — the
// script threw `ReferenceError: __dirname is not defined in ES module scope`
// on line 1 of real work and had therefore never produced a single backup,
// despite SERVER-DEPLOYMENT-TODO.md describing it as "a working backup
// script" that merely needed scheduling. DMS's copy had the identical bug.
// Scheduling it as a Windows task would have hidden this permanently: the
// task reports "completed", the exit code is non-zero, and nobody looks
// until the day the identity database is needed back.
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const mode = process.argv[2] === "production" ? "production" : "development";

// ENV FILE LOADING CONTRACT — the same one src/config.ts enforces: production
// reads .env.production ONLY, anything else reads .env ONLY.
//
// This script used to load .env first and then layer .env.production on top in
// production mode, which is precisely the fault the contract exists to prevent.
// dotenv only overrides the keys the second file actually NAMES, so a
// .env.production that happened not to spell out DATABASE_URL would leave the
// DEVELOPMENT value in place — and this job would quietly dump the `idp` dev
// database every night, report [SUCCESS], and leave `idpprod` with no backup at
// all. That is the worst possible failure mode for a backup: it looks fine.
const envPath = path.resolve(
  __dirname,
  "..",
  mode === "production" ? ".env.production" : ".env",
);
if (!fs.existsSync(envPath)) {
  console.error(
    `[ERROR] ${envPath} does not exist. ${mode} configuration is read from ` +
      "that file only — there is deliberately no fallback to the other one.",
  );
  process.exit(1);
}
loadDotenv({ path: envPath, override: true });

let pgDumpCmd = "pg_dump";
const commonPgPaths = [
  "C:\\Program Files\\PostgreSQL\\18\\bin\\pg_dump.exe",
  "C:\\Program Files\\PostgreSQL\\17\\bin\\pg_dump.exe",
  "C:\\Program Files\\PostgreSQL\\16\\bin\\pg_dump.exe",
  "C:\\Program Files\\PostgreSQL\\15\\bin\\pg_dump.exe",
];
if (process.platform === "win32") {
  const found = commonPgPaths.find((p) => fs.existsSync(p));
  if (found) pgDumpCmd = `"${found}"`;
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.error("[ERROR] DATABASE_URL is not set after loading the env files");
  process.exit(1);
}

let dbNameForFilename = "idp";
try {
  dbNameForFilename = new URL(databaseUrl).pathname.replace(/^\//, "") || "idp";
} catch {
  // fall back to the default label if DATABASE_URL isn't a parseable URL
}

const backupDir = path.resolve(__dirname, "..", "..", "backups");
if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });

const timestamp = new Date().toISOString().replace(/[:.]/g, "-").split(".")[0];
const filename = `${dbNameForFilename}_${mode}_${timestamp}.dump`;
const filepath = path.join(backupDir, filename);
const partPath = `${filepath}.part`;

console.log(`[BACKUP] ${dbNameForFilename} (${mode})...`);

try {
  const command = `${pgDumpCmd} "${databaseUrl}" --format=custom --compress=6 -f "${partPath}"`;
  execSync(command, { stdio: "inherit" });
  fs.renameSync(partPath, filepath);

  console.log(`[SUCCESS] ${filepath}`);

  const RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  for (const file of fs.readdirSync(backupDir)) {
    const fPath = path.join(backupDir, file);
    if (now - fs.statSync(fPath).mtimeMs > RETENTION_MS) {
      fs.unlinkSync(fPath);
      console.log(`[PRUNE] ${file}`);
    }
  }
} catch (error: any) {
  if (fs.existsSync(partPath)) fs.unlinkSync(partPath);
  console.error(`[FAILED] ${error.message}`);
  process.exit(1);
}
