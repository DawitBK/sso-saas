// Pure helpers behind deploy/supervise.cjs, kept apart so they can be unit-tested (backend/tests/supervise.test.ts)
// without spawning anything.
'use strict';

/** Restart delay: 1s, 2s, 4s ... capped. A child that ran a healthy stretch resets the ladder (see ranLongEnough). */
function nextDelayMs(consecutiveShortRuns, capMs = 30_000) {
  const n = Math.max(0, Math.floor(consecutiveShortRuns));
  return Math.min(capMs, 1000 * 2 ** Math.min(n, 10));
}

/** A run counts as healthy (so the backoff resets) once it stayed up this long. */
function ranLongEnough(runMs, thresholdMs = 60_000) {
  return runMs >= thresholdMs;
}

/** KEY=VALUE lines, optional quotes, # comments. Enough for a .env file; not a full dotenv. */
function parseEnvText(text) {
  const out = {};
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    out[key] = value;
  }
  return out;
}

/**
 * Replace {NAME} in a template from `env`; an unknown name is an error, never an empty string. Braces without a dollar sign on
 * purpose: an npm script goes through a shell, and `${PORT}` would be expanded (to nothing) by sh before this ever saw it.
 */
function expandTemplate(template, env) {
  return String(template).replace(/\{([A-Z0-9_]+)\}/g, (_m, name) => {
    const v = env[name];
    if (v === undefined || v === '') throw new Error(`health URL needs ${name}, which is not set (environment or --env-file)`);
    return v;
  });
}

const USAGE =
  'Usage: node supervise.cjs --name <name> [--cwd <dir>] [--env-file <file>] [--env KEY=VALUE]... ' +
  '[--health <url with {PORT}>] [--health-interval <s>] [--health-failures <n>] [--grace <s>] -- <command> [args...]\n' +
  '       node supervise.cjs --stop <name> [--cwd <dir>]';

function parseArgs(argv) {
  const opts = { env: {}, healthIntervalSec: 15, healthFailures: 4, graceSec: 60 };
  const rest = [...argv];
  while (rest.length) {
    const a = rest.shift();
    if (a === '--') { opts.cmd = rest.splice(0); break; }
    const need = () => {
      const v = rest.shift();
      if (v === undefined) throw new Error(`${a} needs a value\n${USAGE}`);
      return v;
    };
    if (a === '--name') opts.name = need();
    else if (a === '--stop') { opts.stop = true; opts.name = need(); }
    else if (a === '--cwd') opts.cwd = need();
    else if (a === '--env-file') opts.envFile = need();
    else if (a === '--env') {
      const kv = need();
      const eq = kv.indexOf('=');
      if (eq < 1) throw new Error(`--env needs KEY=VALUE, got "${kv}"`);
      opts.env[kv.slice(0, eq)] = kv.slice(eq + 1);
    } else if (a === '--health') opts.healthUrl = need();
    else if (a === '--health-interval') opts.healthIntervalSec = Number(need());
    else if (a === '--health-failures') opts.healthFailures = Number(need());
    else if (a === '--grace') opts.graceSec = Number(need());
    else throw new Error(`unknown option ${a}\n${USAGE}`);
  }
  if (!opts.name || !/^[a-z0-9][a-z0-9_-]{0,40}$/i.test(opts.name)) throw new Error(`--name is required (letters, digits, - _)\n${USAGE}`);
  if (!opts.stop && (!opts.cmd || opts.cmd.length === 0)) throw new Error(`a command after -- is required\n${USAGE}`);
  for (const [k, v] of [['--health-interval', opts.healthIntervalSec], ['--health-failures', opts.healthFailures], ['--grace', opts.graceSec]]) {
    if (!Number.isFinite(v) || v < 1) throw new Error(`${k} must be a positive number`);
  }
  return opts;
}

/** A health probe answer counts as alive when it is not a server error; a hung process times out and a dead one refuses. */
function statusIsAlive(status) {
  return Number.isInteger(status) && status >= 100 && status < 500;
}

module.exports = { nextDelayMs, ranLongEnough, parseEnvText, expandTemplate, parseArgs, statusIsAlive, USAGE };
