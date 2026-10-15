// PM2 process definitions for SSO. Optional — `npm run start:prod` (backend)
// and `npm start` (frontend) in two console windows is a complete deployment on
// their own. PM2 only adds auto-restart and reboot survival on top.
//
//   cd SSO && pm2 start deploy/ecosystem.config.cjs && pm2 save
//
// Both apps must be BUILT first (`npm run build` in each), and the frontend must
// have been built with NEXT_PUBLIC_BASE_PATH=/sso for the production Apache
// vhost — basePath is baked in at build time, not read at startup.
const path = require('path');

const root = path.resolve(__dirname, '..');

module.exports = {
  apps: [
    {
      name: 'sso-api',
      cwd: path.join(root, 'backend'),
      script: 'dist/main.js',
      interpreter: 'node',
      instances: 1,
      // NODE_ENV must be set BEFORE the process starts: config.ts reads it from
      // the real process environment to decide which env file to load, and in
      // production loads .env.production ONLY (never .env). This is the same
      // thing `npm run start:prod` does via scripts/run-with-env.cjs.
      env: { NODE_ENV: 'production' },
      max_memory_restart: '768M',
    },
    {
      name: 'sso-web',
      cwd: path.join(root, 'frontend'),
      // NOT `next start`. next.config.ts sets output: "standalone", and Next
      // refuses to serve a standalone build through `next start` ('"next start"
      // does not work with "output: standalone"'). The real entry point is a
      // generated server.js whose depth varies, and .next/static and public/
      // are not traced into the standalone folder — miss that and the app boots
      // but every CSS/JS chunk 404s. scripts/start-standalone.cjs handles all
      // three, and is exactly what `npm start` runs.
      script: 'scripts/start-standalone.cjs',
      args: '7301',
      interpreter: 'node',
      instances: 1,
      env: { NODE_ENV: 'production', PORT: '7301' },
      max_memory_restart: '512M',
    },
  ],
};
