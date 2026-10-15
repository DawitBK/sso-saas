/**
 * What keeps a second SSO process on the same database from misbehaving: sweeps that run once (ops/jobs.ts#runExclusive, against the real
 * dev database's advisory locks) and signing keys that follow the table (jwks.ts#startSigningKeyRefresh, with the loader and reloader injected).
 */
import { pool } from '../src/db/pool.js';
import { runExclusive } from '../src/ops/jobs.js';
import { keySetSignature, startSigningKeyRefresh, stopSigningKeyRefresh } from '../src/jwks.js';

afterAll(async () => {
  stopSigningKeyRefresh();
  await pool.end();
});

describe('runExclusive', () => {
  /** Resolves once the job body is running, i.e. once it certainly holds the lock (no sleeping and hoping, which flakes under load). */
  const holdUntilReleased = () => {
    let release!: () => void;
    let started!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const running = new Promise<void>((r) => { started = r; });
    return { release, running, body: async () => { started(); await gate; } };
  };

  it('runs one copy of a job at a time and lets the next one through afterwards', async () => {
    const a = holdUntilReleased();
    let ranB = 0;
    const first = runExclusive('jest-exclusive', a.body);
    await a.running;
    const b = await runExclusive('jest-exclusive', async () => { ranB += 1; });
    expect(b).toBe(false);
    expect(ranB).toBe(0);
    a.release();
    expect(await first).toBe(true);
    expect(await runExclusive('jest-exclusive', async () => { ranB += 1; })).toBe(true);
    expect(ranB).toBe(1);
  });

  it('different jobs do not block each other, and a failing job still frees its lock', async () => {
    const a = holdUntilReleased();
    const first = runExclusive('jest-job-one', a.body);
    await a.running;
    expect(await runExclusive('jest-job-two', async () => undefined)).toBe(true);
    a.release();
    await first;
    await expect(runExclusive('jest-job-three', async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(await runExclusive('jest-job-three', async () => undefined)).toBe(true);
  });
});

describe('signing key refresh', () => {
  const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it('signature depends on which keys and which one signs first', () => {
    expect(keySetSignature([{ kid: 'a' }, { kid: 'b' }])).toBe('a,b');
    expect(keySetSignature([{ kid: 'b' }, { kid: 'a' }])).not.toBe(keySetSignature([{ kid: 'a' }, { kid: 'b' }]));
  });

  it('reloads the provider only when the key set changed, and keeps the old keys when a read fails', async () => {
    let keys: Array<{ kid: string }> = [{ kid: 'k1' }];
    let failing = false;
    const reload = jest.fn(async () => undefined);
    startSigningKeyRefresh({} as never, [{ kid: 'k1' }] as never, {
      load: async () => { if (failing) throw new Error('db down'); return keys; },
      reload,
      everyMs: 20,
    });

    await tick(90);
    expect(reload).not.toHaveBeenCalled(); // nothing changed

    failing = true;
    keys = [{ kid: 'k2' }, { kid: 'k1' }];
    await tick(90);
    expect(reload).not.toHaveBeenCalled(); // could not read: keep what is loaded, do not guess

    failing = false;
    await tick(90);
    expect(reload).toHaveBeenCalledTimes(1); // rotated elsewhere: now followed, once

    await tick(90);
    expect(reload).toHaveBeenCalledTimes(1); // and not again while it stays the same

    keys = [{ kid: 'k2' }]; // k1's overlap window ended: it stops being published
    await tick(90);
    expect(reload).toHaveBeenCalledTimes(2);
  });
});
