// Shared loader for the two mirror-mode scripts (build-mirror.cjs,
// start-mirror.cjs). Next's OWN env-file convention only covers
// .env.development (next dev) and .env.production (next build/start) — there
// is no built-in way to make `next build`/`next start` consult an arbitrary
// third file, so this parses .env.mirror by hand and sets it on
// process.env before Next ever runs. No `dotenv` dependency: this app never
// added it (unlike GMS's frontend, which already depends on it for the same
// job via scripts/run-next-with-env.js), and a ~15-line parser isn't worth a
// new dependency for one file.
'use strict';
const fs = require('fs');
const path = require('path');

const appDir = path.resolve(__dirname, '..');
const mirrorEnvPath = path.join(appDir, '.env.mirror');

function loadMirrorEnv() {
  if (!fs.existsSync(mirrorEnvPath)) {
    console.error(
      `[mirror] ${mirrorEnvPath} does not exist.\n` +
        'This is the isolated local prod-mirror environment (see root CLAUDE.md) — ' +
        'it is never `.env`/`.env.development` or `.env.production`.',
    );
    process.exit(1);
  }
  for (const rawLine of fs.readFileSync(mirrorEnvPath, 'utf8').split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
  process.env.NODE_ENV = 'mirror';
  process.env.NEXT_DIST_DIR = '.next-mirror';
}

module.exports = { loadMirrorEnv, appDir };
