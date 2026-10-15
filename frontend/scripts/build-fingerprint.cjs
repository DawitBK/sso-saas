// Guards against the exact bug hit 2026-09-21: Next.js bakes env-derived
// config (this app's next.config.ts `rewrites()` destinations, and every
// NEXT_PUBLIC_* value in the client bundle) into the configured Next distDir
// (`.next` by default) AT BUILD TIME. A
// standalone server.js re-read at process start does NOT re-evaluate any of
// that — restarting after changing `.env.mirror`/`.env.production` silently
// keeps serving whatever was true the last time `next build` ran. That's how
// the mirror frontend ended up proxying `/authorize`, `/portal`, `/bridge`
// etc. straight at dev's port 7300 for an entire session: the process, the
// checkout and `.env.mirror` were all correct — the build just predated them.
//
// Fix is fail-fast, not smarter env-loading: hash the env file a build
// consumed and stamp it into that distDir; before
// serving that build, recompute the hash and refuse to start on a mismatch
// (or a missing stamp) instead of silently serving stale config. A
// comment-only env edit forces an unneeded rebuild — that's the acceptable
// false-positive side of this trade, not the silent-staleness side.
//
// Usage: node scripts/build-fingerprint.cjs write <envFile>   (after `next build`)
//        node scripts/build-fingerprint.cjs check <envFile>   (before serving)
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const appDir = path.resolve(__dirname, '..');
function getStampPath(envFile) {
  const distDir = process.env.NEXT_DIST_DIR || (envFile === '.env.mirror' ? '.next-mirror' : '.next');
  return path.join(appDir, distDir, 'BUILD_ENV_FINGERPRINT.json');
}

function hashEnvFile(envFile) {
  const envPath = path.join(appDir, envFile);
  if (!fs.existsSync(envPath)) {
    console.error(`[build-fingerprint] ${envPath} does not exist.`);
    process.exit(1);
  }
  return crypto.createHash('sha256').update(fs.readFileSync(envPath)).digest('hex');
}

function writeFingerprint(envFile) {
  const hash = hashEnvFile(envFile);
  const stampPath = getStampPath(envFile);
  fs.mkdirSync(path.dirname(stampPath), { recursive: true });
  fs.writeFileSync(
    stampPath,
    JSON.stringify({ envFile, hash, builtAt: new Date().toISOString() }, null, 2),
  );
  console.log(`[build-fingerprint] stamped ${envFile} (${hash.slice(0, 12)}…) into ${path.relative(appDir, stampPath)}`);
}

function checkFingerprintOrExit(envFile) {
  const currentHash = hashEnvFile(envFile);
  const stampPath = getStampPath(envFile);
  if (!fs.existsSync(stampPath)) {
    console.error(
      `\n[build-fingerprint] REFUSING TO START: no build fingerprint found at ` +
        `${path.relative(appDir, stampPath)}.\n` +
        `This build predates the freshness check, or .next was rebuilt by hand. ` +
        `Run \`npm run build${envFile === '.env.mirror' ? ':mirror' : ''}\` before starting.\n`,
    );
    process.exit(1);
  }
  const stamp = JSON.parse(fs.readFileSync(stampPath, 'utf8'));
  if (stamp.envFile !== envFile || stamp.hash !== currentHash) {
    console.error(
      `\n[build-fingerprint] REFUSING TO START: the compiled build does not match ` +
        `the current ${envFile}.\n` +
        `Built against: ${stamp.envFile ?? '(unknown)'} @ ${(stamp.hash ?? '').slice(0, 12) || '(none)'}…  ` +
        `(${stamp.builtAt ?? 'unknown time'})\n` +
        `${envFile} now hashes to:  ${currentHash.slice(0, 12)}…\n` +
        `Next.js bakes rewrites()/NEXT_PUBLIC_* values in at build time — a restart ` +
        `alone will keep serving the OLD values, silently. Run \`npm run build${envFile === '.env.mirror' ? ':mirror' : ''}\` first.\n`,
    );
    process.exit(1);
  }
  console.log(`[build-fingerprint] OK — build matches current ${envFile} (${currentHash.slice(0, 12)}…)`);
}

if (require.main === module) {
  const [, , action, envFile] = process.argv;
  if (!action || !envFile) {
    console.error('Usage: node scripts/build-fingerprint.cjs <write|check> <envFile>');
    process.exit(1);
  }
  if (action === 'write') writeFingerprint(envFile);
  else if (action === 'check') checkFingerprintOrExit(envFile);
  else {
    console.error(`Unknown action "${action}" (expected "write" or "check")`);
    process.exit(1);
  }
}

module.exports = { writeFingerprint, checkFingerprintOrExit };
