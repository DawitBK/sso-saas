import { CircuitBreaker, CircuitOpenError } from '../src/infrastructure/circuitBreaker.js';

function make(opts: { failureThreshold?: number; openMs?: number } = {}) {
  let t = 1_000_000;
  const breaker = new CircuitBreaker({ name: 'dms', failureThreshold: 3, openMs: 30_000, ...opts, now: () => t });
  return { breaker, advance: (ms: number) => { t += ms; } };
}
const fail = () => Promise.reject(new Error('down'));
const ok = () => Promise.resolve('fine');

describe('CircuitBreaker', () => {
  it('passes calls through while healthy and reports closed', async () => {
    const { breaker } = make();
    await expect(breaker.run(ok)).resolves.toBe('fine');
    expect(breaker.state()).toBe('closed');
  });

  it('opens after the threshold of consecutive failures and then refuses without calling', async () => {
    const { breaker } = make();
    for (let i = 0; i < 3; i++) await expect(breaker.run(fail)).rejects.toThrow('down');
    expect(breaker.state()).toBe('open');
    const spy = jest.fn(ok);
    await expect(breaker.run(spy)).rejects.toBeInstanceOf(CircuitOpenError);
    expect(spy).not.toHaveBeenCalled();
    expect(breaker.snapshot().shortCircuited).toBe(1);
  });

  it('a success in between resets the count', async () => {
    const { breaker } = make();
    await expect(breaker.run(fail)).rejects.toThrow();
    await expect(breaker.run(fail)).rejects.toThrow();
    await breaker.run(ok);
    await expect(breaker.run(fail)).rejects.toThrow();
    await expect(breaker.run(fail)).rejects.toThrow();
    expect(breaker.state()).toBe('closed');
  });

  it('lets one trial through after the open period; success closes it', async () => {
    const { breaker, advance } = make();
    for (let i = 0; i < 3; i++) await expect(breaker.run(fail)).rejects.toThrow();
    advance(30_000);
    expect(breaker.state()).toBe('half-open');
    await expect(breaker.run(ok)).resolves.toBe('fine');
    expect(breaker.state()).toBe('closed');
  });

  it('a failed trial re-opens it for the full period', async () => {
    const { breaker, advance } = make();
    for (let i = 0; i < 3; i++) await expect(breaker.run(fail)).rejects.toThrow();
    advance(30_000);
    await expect(breaker.run(fail)).rejects.toThrow('down');
    expect(breaker.state()).toBe('open');
    advance(29_000);
    expect(breaker.state()).toBe('open');
    advance(1_000);
    expect(breaker.state()).toBe('half-open');
  });

  it('while the single trial is running, other callers are refused', async () => {
    const { breaker, advance } = make();
    for (let i = 0; i < 3; i++) await expect(breaker.run(fail)).rejects.toThrow();
    advance(30_000);
    let release: (v: string) => void = () => {};
    const slow = breaker.run(() => new Promise<string>((r) => { release = r; }));
    await expect(breaker.run(ok)).rejects.toBeInstanceOf(CircuitOpenError);
    release('done');
    await expect(slow).resolves.toBe('done');
  });

  it('snapshot reports timestamps and when the next trial is due', async () => {
    const { breaker } = make();
    for (let i = 0; i < 3; i++) await expect(breaker.run(fail)).rejects.toThrow();
    const s = breaker.snapshot();
    expect(s).toMatchObject({ name: 'dms', state: 'open', consecutiveFailures: 3 });
    expect(s.lastFailureAt).not.toBeNull();
    expect(s.retryAt).not.toBeNull();
  });

  it('clamps nonsense options', async () => {
    const { breaker } = make({ failureThreshold: 0, openMs: 5 });
    await expect(breaker.run(fail)).rejects.toThrow();
    expect(breaker.state()).toBe('open');
  });
});
