// A small process supervisor for SSO, in plain Node (no PM2, no service wrapper: this server runs Node only).
//
// WHY IT EXISTS. SSO is the front door to every system, and it is deliberately written to EXIT on an unhandled rejection or
// uncaught exception (backend/src/main.ts: an identity provider running from an unknown internal state is worse than one that
// restarts clean). On the live server production-start.bat starts it with a bare `start cmd /k`, so nothing brought it back, and
// deploy/uptime-monitor.ps1 only alerts. Until this existed, one bug meant nobody could sign in to anything until someone
// remembered to look.
//
// WHAT IT DOES
//   - starts the command and restarts it whenever it exits, for any reason, with a 1s, 2s, 4s ... 30s back-off that resets once a run
//     stays up for a minute (a crash loop is slowed down, a one-off crash costs one second);
//   - optional watchdog (--health): probes a LIVENESS URL and kills and restarts a process that is up but hung. Liveness only, on
//     purpose: a database outage must not make the supervisor restart-loop a backend that is correctly waiting for it;
//   - one supervisor per --name (a lock file with a heartbeat), so re-running production-start.bat cannot start a second copy that
//     fights the first for the port;
//   - a log (logs/supervisor-<name>.log, rotated at 5 MB) and a state file (logs/supervisor-<name>.json: restarts, last exit);
//   - `--stop <name>` ends the supervisor AND its child. Killing only the child just makes it come back, which is the point.
//
// Usage: see supervise-lib.cjs (USAGE). Examples are the `start:prod:supervised` and `start:mirror:supervised` npm scripts.
'use strict';

const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawn, spawnSync } = require('child_process');
const lib = require('./supervise-lib.cjs');

const HEARTBEAT_MS = 10_000;
const LOCK_STALE_MS = 60_000;
const LOG_MAX_BYTES = 5 * 1024 * 1024;

let opts;
try {
  opts = lib.parseArgs(process.argv.slice(2));
} catch (err) {
  console.error(err.message);
  process.exit(2);
}

const cwd = path.resolve(opts.cwd || process.cwd());
// --log-dir moves the lock, state and log files out of the working directory (a release folder must stay exactly as it was verified).
const logsDir = opts.logDir ? path.resolve(opts.logDir) : path.join(cwd, 'logs');
fs.mkdirSync(logsDir, { recursive: true });
const lockPath = path.join(logsDir, `supervisor-${opts.name}.lock`);
const statePath = path.join(logsDir, `supervisor-${opts.name}.json`);
const logPath = path.join(logsDir, `supervisor-${opts.name}.log`);

function log(message) {
  const line = `${new Date().toISOString()} [supervisor:${opts.name}] ${message}`;
  console.log(line);
  try {
    if (fs.existsSync(logPath) && fs.statSync(logPath).size > LOG_MAX_BYTES) fs.renameSync(logPath, `${logPath}.1`);
    fs.appendFileSync(logPath, `${line}\n`);
  } catch {
    // a full disk or a locked log must never stop the supervisor itself
  }
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM';
  }
}

function killTree(pid) {
  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true });
  } else {
    try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
    setTimeout(() => { try { process.kill(pid, 'SIGKILL'); } catch { /* already gone */ } }, 5000).unref();
  }
}

function readLock() {
  try {
    const stat = fs.statSync(lockPath);
    const body = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
    return { pid: Number(body.pid), ageMs: Date.now() - stat.mtimeMs };
  } catch {
    return null;
  }
}

if (opts.stop) {
  const lock = readLock();
  if (!lock || !pidAlive(lock.pid) || lock.ageMs > LOCK_STALE_MS) {
    console.log(`[supervisor:${opts.name}] not running.`);
    try { fs.unlinkSync(lockPath); } catch { /* none */ }
    process.exit(0);
  }
  killTree(lock.pid);
  try { fs.unlinkSync(lockPath); } catch { /* none */ }
  console.log(`[supervisor:${opts.name}] stopped (pid ${lock.pid} and its child).`);
  process.exit(0);
}

// One supervisor per name. A live heartbeat means another copy owns it; a stale one (or a dead pid) is taken over.
const existing = readLock();
if (existing && existing.pid !== process.pid && pidAlive(existing.pid) && existing.ageMs <= LOCK_STALE_MS) {
  console.log(`[supervisor:${opts.name}] already supervised by pid ${existing.pid}; nothing to do.`);
  process.exit(0);
}
function writeLock() {
  try { fs.writeFileSync(lockPath, JSON.stringify({ pid: process.pid, startedAt: startedAt.toISOString() })); } catch { /* retried on the next heartbeat */ }
}
const startedAt = new Date();
writeLock();
setInterval(writeLock, HEARTBEAT_MS).unref();

const fileEnv = opts.envFile ? lib.parseEnvText(fs.readFileSync(path.resolve(cwd, opts.envFile), 'utf8')) : {};
const probeEnv = { ...fileEnv, ...process.env, ...opts.env };
let healthUrl = null;
if (opts.healthUrl) {
  try {
    // A server bound to every interface is still probed over loopback.
    const host = probeEnv.HOST && !['0.0.0.0', '::', '[::]'].includes(probeEnv.HOST) ? probeEnv.HOST : '127.0.0.1';
    healthUrl = lib.expandTemplate(opts.healthUrl, { ...probeEnv, HOST: host });
  } catch (err) {
    log(`FATAL: ${err.message}`);
    process.exit(2);
  }
}

const state = { name: opts.name, supervisorPid: process.pid, childPid: null, startedAt: startedAt.toISOString(), restarts: 0, watchdogKills: 0, lastExit: null, lastHealthOkAt: null };
function saveState() {
  try { fs.writeFileSync(statePath, JSON.stringify(state, null, 2)); } catch { /* informational only */ }
}

let child = null;
let childStartedAt = 0;
let stopping = false;
let shortRuns = 0;
let healthFailures = 0;
let killedByWatchdog = false;

function start() {
  const [cmd, ...args] = opts.cmd;
  const exe = cmd === 'node' ? process.execPath : cmd;
  childStartedAt = Date.now();
  healthFailures = 0;
  killedByWatchdog = false;
  child = spawn(exe, args, { cwd, stdio: 'inherit', windowsHide: true, env: { ...process.env, ...opts.env } });
  state.childPid = child.pid ?? null;
  saveState();
  log(`started pid ${child.pid}: ${opts.cmd.join(' ')}`);

  child.on('error', (err) => {
    log(`could not start the command: ${err.message}`);
  });
  child.on('exit', (code, signal) => {
    const ranMs = Date.now() - childStartedAt;
    state.childPid = null;
    state.lastExit = { code, signal, at: new Date().toISOString(), ranSeconds: Math.round(ranMs / 1000), reason: killedByWatchdog ? 'watchdog' : 'exit' };
    child = null;
    if (stopping) { saveState(); return; }
    shortRuns = killedByWatchdog || lib.ranLongEnough(ranMs) ? 0 : shortRuns + 1;
    const delay = killedByWatchdog ? 1000 : lib.nextDelayMs(Math.max(0, shortRuns - 1));
    state.restarts += 1;
    saveState();
    log(`exited (code ${code}, signal ${signal}) after ${Math.round(ranMs / 1000)}s; restarting in ${Math.round(delay / 1000)}s (restart #${state.restarts})`);
    setTimeout(start, delay);
  });
}

function probe() {
  return new Promise((resolve) => {
    const req = http.get(healthUrl, { timeout: 5000 }, (res) => {
      res.resume();
      resolve(lib.statusIsAlive(res.statusCode));
    });
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

if (healthUrl) {
  log(`watchdog on ${healthUrl} every ${opts.healthIntervalSec}s; restarts after ${opts.healthFailures} failed probes (grace ${opts.graceSec}s after each start)`);
  let probing = false;
  setInterval(async () => {
    // One probe at a time, and nothing once a kill is under way: a probe can take its full 5s timeout, longer than the interval.
    if (!child || stopping || probing || killedByWatchdog) return;
    if (Date.now() - childStartedAt < opts.graceSec * 1000) return;
    probing = true;
    try {
      if (await probe()) {
        healthFailures = 0;
        state.lastHealthOkAt = new Date().toISOString();
        return;
      }
      healthFailures += 1;
      log(`liveness probe failed (${healthFailures}/${opts.healthFailures})`);
      if (healthFailures >= opts.healthFailures && child) {
        state.watchdogKills += 1;
        killedByWatchdog = true;
        log(`not answering; killing pid ${child.pid} so it restarts`);
        killTree(child.pid);
      }
    } finally {
      probing = false;
    }
  }, opts.healthIntervalSec * 1000).unref();
}

function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log(`${signal}: stopping`);
  if (child) killTree(child.pid);
  try { fs.unlinkSync(lockPath); } catch { /* none */ }
  setTimeout(() => process.exit(0), 500).unref();
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('exit', () => {
  try {
    const lock = readLock();
    if (lock && lock.pid === process.pid) fs.unlinkSync(lockPath);
  } catch { /* none */ }
});

start();
