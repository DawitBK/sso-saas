// Launches a Next.js `output: "standalone"` build, handling the three things
// that make `npm run start` fail on a standalone build:
//
//  1. `next start` does not serve a standalone build at all (Next warns:
//     '"next start" does not work with "output: standalone"'). The real entry
//     point is the generated server.js.
//
//  2. That server.js is NOT always at .next/standalone/server.js. Next mirrors
//     the app's path relative to whatever it infers as the monorepo root, so in
//     an npm workspace (DMS declares workspaces:[backend,frontend] with
//     node_modules at DMS/) it lands at .next/standalone/frontend/server.js,
//     while a standalone app with its own node_modules gets the flat path. We
//     locate it instead of hardcoding either guess.
//
//  3. `next build` does NOT copy .next/static (or public/) into the standalone
//     folder — those files aren't traced. Miss that and the app boots fine but
//     every CSS/JS chunk 404s, so it renders unstyled and looks "broken" for a
//     reason that has nothing to do with the server.
//
// Port: taken from $PORT if set, else the default passed as argv[2].
// Usage: node scripts/start-standalone.cjs 7101
'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const appDir = path.resolve(__dirname, '..');
const standaloneDir = path.join(appDir, '.next', 'standalone');
const defaultPort = process.argv[2] || '3000';

function findServerJs(dir, depth) {
  if (depth > 4) return null;
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return null;
  }
  // Prefer a server.js in this directory before descending.
  for (const e of entries) {
    if (e.isFile() && e.name === 'server.js') return path.join(dir, e.name);
  }
  for (const e of entries) {
    // Skip node_modules and dot-dirs (.next inside standalone holds no entry point).
    if (!e.isDirectory() || e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const hit = findServerJs(path.join(dir, e.name), depth + 1);
    if (hit) return hit;
  }
  return null;
}

if (!fs.existsSync(standaloneDir)) {
  console.error(
    `[start-standalone] ${standaloneDir} does not exist.\n` +
      `Run \`npm run build\` first, and confirm next.config sets output: "standalone".`,
  );
  process.exit(1);
}

const serverJs = findServerJs(standaloneDir, 0);
if (!serverJs) {
  console.error(`[start-standalone] no server.js found under ${standaloneDir}. Re-run \`npm run build\`.`);
  process.exit(1);
}

// Mirror the untraced assets next to the server, every start — cheap, and it
// self-heals a build that was run without this step.
const serverDir = path.dirname(serverJs);
for (const [from, to] of [
  [path.join(appDir, '.next', 'static'), path.join(serverDir, '.next', 'static')],
  [path.join(appDir, 'public'), path.join(serverDir, 'public')],
]) {
  if (fs.existsSync(from)) fs.cpSync(from, to, { recursive: true, force: true });
}

const port = process.env.PORT || defaultPort;
console.log(`[start-standalone] ${path.relative(appDir, serverJs)} on port ${port}`);

const result = spawnSync(process.execPath, [serverJs], {
  stdio: 'inherit',
  env: { ...process.env, PORT: port },
});
process.exit(typeof result.status === 'number' ? result.status : 1);
