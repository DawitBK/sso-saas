// Runs a command with NODE_ENV forced to the given mode, regardless of shell
// (PowerShell has no `set X=Y &&`; cmd.exe has no `$env:X=`). Mirrors GMS's
// scripts/run-sequelize-cli.js.
'use strict';
const { spawnSync } = require('child_process');

const mode = process.argv[2];
const cmd = process.argv.slice(3).join(' ');

if (!mode || !cmd) {
  console.error('Usage: node scripts/run-with-env.js <development|production> <command...>');
  process.exit(1);
}

const result = spawnSync(cmd, {
  stdio: 'inherit',
  shell: true,
  env: { ...process.env, NODE_ENV: mode },
});

process.exit(typeof result.status === 'number' ? result.status : 1);
