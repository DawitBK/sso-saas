// Runs the standalone build against .env.mirror. `next start` cannot serve an
// `output: "standalone"` build at all (see start-standalone.cjs), and even a
// plain `next start` would only ever auto-load .env.production — never a
// mirror file — so this loads .env.mirror by hand and then delegates to the
// existing start-standalone.cjs entry point unchanged.
// Usage: node scripts/start-mirror.cjs
'use strict';
const { loadMirrorEnv } = require('./mirror-env.cjs');

loadMirrorEnv();
require('./start-standalone.cjs');
