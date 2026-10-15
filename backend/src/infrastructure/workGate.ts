/**
 * A bounded gate for expensive work, so a flood of it cannot starve everything else.
 *
 * The expensive work here is checking a password. SSO hashes with scrypt at N=2^17 (about 128 MB of memory and a good fraction of a
 * second of CPU per attempt) on libuv's small thread pool, which Node ALSO uses for DNS lookups and file access. Sign-in attempts are
 * unauthenticated, and the per-address rate limit only slows one address; a few hundred attempts from many addresses would queue
 * unbounded scrypt jobs, exhaust memory, and delay every other request that needs the thread pool, including the token endpoint
 * every system depends on. The gate runs at most `max` at a time, lets at most `maxQueue` wait, and gives up on a waiter after
 * `maxWaitMs`: past that the caller is told "busy, try again" (a 503) instead of everybody slowing down together.
 */
export class GateBusyError extends Error {
  constructor(public readonly reason: 'queue-full' | 'wait-timeout') {
    super(reason === 'queue-full' ? 'Too many sign-in checks are waiting.' : 'Waited too long for a sign-in check.');
    this.name = 'GateBusyError';
  }
}

interface Waiter {
  resolve: () => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export interface GateStats {
  max: number;
  running: number;
  waiting: number;
  refused: number;
  completed: number;
}

export class WorkGate {
  private running = 0;
  private refused = 0;
  private completed = 0;
  private readonly queue: Waiter[] = [];

  constructor(
    private readonly max: number,
    private readonly maxQueue: number,
    private readonly maxWaitMs: number,
  ) {
    if (max < 1) throw new Error('WorkGate max must be at least 1');
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.completed += 1;
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.running < this.max) {
      this.running += 1;
      return Promise.resolve();
    }
    if (this.queue.length >= this.maxQueue) {
      this.refused += 1;
      return Promise.reject(new GateBusyError('queue-full'));
    }
    return new Promise<void>((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const i = this.queue.indexOf(waiter);
          if (i !== -1) this.queue.splice(i, 1);
          this.refused += 1;
          reject(new GateBusyError('wait-timeout'));
        }, this.maxWaitMs),
      };
      waiter.timer.unref?.();
      this.queue.push(waiter);
    });
  }

  private release(): void {
    const next = this.queue.shift();
    if (next) {
      clearTimeout(next.timer);
      next.resolve(); // the slot passes straight to the waiter: `running` stays the same
    } else {
      this.running -= 1;
    }
  }

  stats(): GateStats {
    return { max: this.max, running: this.running, waiting: this.queue.length, refused: this.refused, completed: this.completed };
  }
}
