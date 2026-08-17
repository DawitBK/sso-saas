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
      env: { NODE_ENV: 'production' },
      max_memory_restart: '768M',
    },
    {
      name: 'sso-web',
      cwd: path.join(root, 'frontend'),
      script: 'node_modules/next/dist/bin/next',
      args: 'start -p 7301',
      interpreter: 'node',
      instances: 1,
      env: { NODE_ENV: 'production' },
      max_memory_restart: '512M',
    },
  ],
};
