// Runs the real supervisor (deploy/supervise.cjs) against real child processes and checks what it promises:
//   1. a child that crashes is started again, with the back-off growing;
//   2. a child that is up but no longer answering its health URL is killed and started again;
//   3. a second supervisor with the same name refuses to start;
//   4. `--stop` ends the supervisor and its child.
// Nothing here touches SSO itself. Usage: node test-scripts/supervise-live.mjs   (about 40 seconds)
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SUP = path.resolve(here, '..', '..', 'deploy', 'supervise.cjs');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'supervise-live-'));
fs.writeFileSync(path.join(work, 'crash.js'), "console.log('up'); setTimeout(() => { throw new Error('boom'); }, 200);\n");
fs.writeFileSync(
  path.join(work, 'hang.js'),
  "const http=require('http');let n=0;http.createServer((q,r)=>{n++;if(n>1)return;r.end('ok');}).listen(Number(process.env.PORT));\n",
);

let failures = 0;
function check(name, ok, detail = '') {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  -  ${detail}`}`);
  if (!ok) failures += 1;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const readLog = (name) => {
  try { return fs.readFileSync(path.join(work, 'logs', `supervisor-${name}.log`), 'utf8'); } catch { return ''; }
};
const freePort = () => new Promise((resolve) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
});
const listening = (port) => new Promise((resolve) => {
  const s = net.connect(port, '127.0.0.1');
  s.on('connect', () => { s.destroy(); resolve(true); });
  s.on('error', () => resolve(false));
});
const start = (name, args, env = {}) =>
  spawn(process.execPath, [SUP, '--name', name, '--cwd', work, ...args], { env: { ...process.env, ...env }, stdio: 'ignore' });

// 1. crash loop
const crash = start('crash', ['--', 'node', 'crash.js']);
await sleep(8000);
const crashLog = readLog('crash');
const starts = (crashLog.match(/started pid/g) ?? []).length;
check('a crashing child is started again', starts >= 3, `starts=${starts}`);
check('the delay between restarts grows', /restarting in 1s/.test(crashLog) && /restarting in 2s/.test(crashLog), crashLog.slice(-400));
spawnSync(process.execPath, [SUP, '--stop', 'crash', '--cwd', work]);
crash.kill();

// 2 and 3. a child that stops answering
const port = await freePort();
const hang = start('hang', ['--health', 'http://127.0.0.1:{PORT}/', '--health-interval', '2', '--health-failures', '2', '--grace', '2', '--', 'node', 'hang.js'], { PORT: String(port) });
await sleep(1500);
check('the supervised child is listening', await listening(port));
const second = spawnSync(process.execPath, [SUP, '--name', 'hang', '--cwd', work, '--', 'node', 'hang.js'], { env: { ...process.env, PORT: String(port) }, encoding: 'utf8' });
check('a second supervisor with the same name refuses', /already supervised/.test(second.stdout ?? ''), second.stdout);
await sleep(20_000);
const hangLog = readLog('hang');
check('a hung child is detected and killed', /killing pid/.test(hangLog), hangLog.slice(-500));
check('and started again afterwards', (hangLog.match(/started pid/g) ?? []).length >= 2, hangLog.slice(-500));

// 4. stop
const stop = spawnSync(process.execPath, [SUP, '--stop', 'hang', '--cwd', work], { encoding: 'utf8' });
await sleep(2000);
check('--stop reports it stopped the supervisor', /stopped/.test(stop.stdout ?? ''), stop.stdout);
check('--stop also ends the child (the port is free)', !(await listening(port)));
hang.kill();

fs.rmSync(work, { recursive: true, force: true });
console.log(failures === 0 ? '\nAll supervisor checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
