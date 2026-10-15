// The pure parts of the process supervisor (SSO/deploy/supervise-lib.cjs). The process handling itself (restart, watchdog,
// single-instance lock, --stop) is exercised against real child processes by test-scripts/supervise-live.mjs.
import path from 'node:path';

const lib = require(path.resolve(process.cwd(), '..', 'deploy', 'supervise-lib.cjs')) as {
  nextDelayMs: (n: number, cap?: number) => number;
  ranLongEnough: (ms: number, threshold?: number) => boolean;
  parseEnvText: (text: string) => Record<string, string>;
  expandTemplate: (template: string, env: Record<string, string | undefined>) => string;
  parseArgs: (argv: string[]) => Record<string, any>;
  statusIsAlive: (status: number) => boolean;
};

describe('restart back-off', () => {
  it('doubles from one second and is capped', () => {
    expect([0, 1, 2, 3, 4].map((n) => lib.nextDelayMs(n))).toEqual([1000, 2000, 4000, 8000, 16000]);
    expect(lib.nextDelayMs(5)).toBe(30_000);
    expect(lib.nextDelayMs(50)).toBe(30_000);
  });
  it('a negative or fractional count behaves like zero or its floor', () => {
    expect(lib.nextDelayMs(-3)).toBe(1000);
    expect(lib.nextDelayMs(2.9)).toBe(4000);
  });
  it('a run counts as healthy only after a minute', () => {
    expect(lib.ranLongEnough(59_999)).toBe(false);
    expect(lib.ranLongEnough(60_000)).toBe(true);
  });
});

describe('env file parsing', () => {
  it('reads plain, quoted and commented values', () => {
    const env = lib.parseEnvText('# comment\nPORT=7300\nHOST="127.0.0.1"\nNAME=\'a b\'\nX=1 # trailing\n\n=bad\nNOEQUALS\n');
    expect(env).toEqual({ PORT: '7300', HOST: '127.0.0.1', NAME: 'a b', X: '1' });
  });
  it('copes with Windows line endings', () => {
    expect(lib.parseEnvText('PORT=9300\r\nHOST=127.0.0.1\r\n')).toEqual({ PORT: '9300', HOST: '127.0.0.1' });
  });
});

describe('health URL template', () => {
  it('fills the placeholders', () => {
    expect(lib.expandTemplate('http://{HOST}:{PORT}/health', { HOST: '127.0.0.1', PORT: '7300' })).toBe('http://127.0.0.1:7300/health');
  });
  it('refuses to guess a missing value', () => {
    expect(() => lib.expandTemplate('http://127.0.0.1:{PORT}/', {})).toThrow(/PORT/);
    expect(() => lib.expandTemplate('http://127.0.0.1:{PORT}/', { PORT: '' })).toThrow(/PORT/);
  });
});

describe('argument parsing', () => {
  it('parses a full command line', () => {
    const o = lib.parseArgs(['--name', 'sso-backend', '--env', 'NODE_ENV=production', '--health', 'http://x/{PORT}', '--grace', '30', '--', 'node', 'dist/main.js', '--flag']);
    expect(o.name).toBe('sso-backend');
    expect(o.env).toEqual({ NODE_ENV: 'production' });
    expect(o.graceSec).toBe(30);
    expect(o.cmd).toEqual(['node', 'dist/main.js', '--flag']);
  });
  it('needs a name and a command', () => {
    expect(() => lib.parseArgs(['--', 'node'])).toThrow(/--name/);
    expect(() => lib.parseArgs(['--name', 'a'])).toThrow(/command/);
  });
  it('--stop needs only a name', () => {
    expect(lib.parseArgs(['--stop', 'sso-backend'])).toMatchObject({ stop: true, name: 'sso-backend' });
  });
  it('rejects unknown options, bad names and non-positive numbers', () => {
    expect(() => lib.parseArgs(['--name', 'a', '--nope', '--', 'node'])).toThrow(/unknown option/);
    expect(() => lib.parseArgs(['--name', '../x', '--', 'node'])).toThrow(/--name/);
    expect(() => lib.parseArgs(['--name', 'a', '--grace', '0', '--', 'node'])).toThrow(/positive/);
    expect(() => lib.parseArgs(['--name', 'a', '--env', 'NOEQUALS', '--', 'node'])).toThrow(/KEY=VALUE/);
  });
});

describe('what the watchdog treats as alive', () => {
  it('anything below 500 (a hung process times out, a dead one refuses; a 302 or 404 still proves it is answering)', () => {
    for (const s of [200, 204, 302, 404, 429]) expect(lib.statusIsAlive(s)).toBe(true);
    for (const s of [500, 502, 503]) expect(lib.statusIsAlive(s)).toBe(false);
  });
});
