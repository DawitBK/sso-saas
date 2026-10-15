import { GateBusyError, WorkGate } from '../src/infrastructure/workGate.js';

const tick = () => new Promise<void>((r) => setImmediate(r));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}

describe('WorkGate', () => {
  it('runs up to max at once and queues the rest in order', async () => {
    const gate = new WorkGate(2, 10, 5_000);
    const order: string[] = [];
    const a = deferred();
    const b = deferred();
    const c = deferred();
    const pa = gate.run(async () => { order.push('a'); await a.promise; });
    const pb = gate.run(async () => { order.push('b'); await b.promise; });
    const pc = gate.run(async () => { order.push('c'); await c.promise; });
    await tick();
    expect(order).toEqual(['a', 'b']);
    expect(gate.stats()).toMatchObject({ running: 2, waiting: 1 });
    a.resolve();
    await pa;
    await tick();
    expect(order).toEqual(['a', 'b', 'c']);
    b.resolve();
    c.resolve();
    await Promise.all([pb, pc]);
    expect(gate.stats()).toMatchObject({ running: 0, waiting: 0, completed: 3, refused: 0 });
  });

  it('refuses at once when the queue is full', async () => {
    const gate = new WorkGate(1, 1, 5_000);
    const hold = deferred();
    const running = gate.run(() => hold.promise);
    const waiting = gate.run(async () => undefined);
    await tick();
    await expect(gate.run(async () => undefined)).rejects.toMatchObject({ name: 'GateBusyError', reason: 'queue-full' });
    expect(gate.stats().refused).toBe(1);
    hold.resolve();
    await Promise.all([running, waiting]);
  });

  it('gives up on a waiter after the wait limit, and frees the slot for others', async () => {
    const gate = new WorkGate(1, 5, 30);
    const hold = deferred();
    const running = gate.run(() => hold.promise);
    await expect(gate.run(async () => undefined)).rejects.toBeInstanceOf(GateBusyError);
    expect(gate.stats()).toMatchObject({ waiting: 0, refused: 1 });
    hold.resolve();
    await running;
    await expect(gate.run(async () => 'ok')).resolves.toBe('ok');
  });

  it('a task that throws still frees its slot', async () => {
    const gate = new WorkGate(1, 5, 1_000);
    await expect(gate.run(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    await expect(gate.run(async () => 'next')).resolves.toBe('next');
    expect(gate.stats().running).toBe(0);
  });

  it('never exceeds max under a burst', async () => {
    const gate = new WorkGate(3, 200, 5_000);
    let live = 0;
    let peak = 0;
    await Promise.all(Array.from({ length: 60 }, () => gate.run(async () => {
      live += 1;
      peak = Math.max(peak, live);
      await tick();
      live -= 1;
    })));
    expect(peak).toBeLessThanOrEqual(3);
    expect(gate.stats().completed).toBe(60);
  });

  it('rejects a gate that could never run anything', () => {
    expect(() => new WorkGate(0, 1, 1)).toThrow();
  });
});
