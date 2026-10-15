/**
 * A small circuit breaker for calls SSO makes to another system while a person is waiting to sign in.
 *
 * The DMS role lookup runs inside token issuance (auth/client-role-claims.ts), bounded by DMS_INTERNAL_TIMEOUT_MS (4 s). With DMS
 * down, every sign-in used to wait that whole timeout before being answered without the DMS roles. After `failureThreshold`
 * consecutive failures the breaker OPENS: the next calls fail at once (no network, no wait) for `openMs`, then ONE trial call is
 * allowed through (half-open); its success closes the breaker, its failure re-opens it. Sign-ins stay fast and DMS is not hammered
 * while it recovers.
 *
 * The clock is injectable so the behaviour is unit-tested without sleeping (tests/circuit-breaker.test.ts).
 */

export type BreakerState = 'closed' | 'open' | 'half-open';

export class CircuitOpenError extends Error {
  constructor(public readonly breaker: string, public readonly retryInMs: number) {
    super(`${breaker} is failing; calls are paused for another ${Math.ceil(retryInMs / 1000)}s`);
    this.name = 'CircuitOpenError';
  }
}

export interface BreakerSnapshot {
  name: string;
  state: BreakerState;
  consecutiveFailures: number;
  /** Total calls refused while open since the process started. */
  shortCircuited: number;
  lastFailureAt: string | null;
  lastSuccessAt: string | null;
  /** When an open breaker lets the next trial through (ISO), else null. */
  retryAt: string | null;
}

export interface BreakerOptions {
  name: string;
  failureThreshold?: number;
  openMs?: number;
  now?: () => number;
}

export class CircuitBreaker {
  private failures = 0;
  private openedAt: number | null = null;
  private trialInFlight = false;
  private shortCircuitedTotal = 0;
  private lastFailure: number | null = null;
  private lastSuccess: number | null = null;
  private readonly threshold: number;
  private readonly openMs: number;
  private readonly now: () => number;
  readonly name: string;

  constructor(opts: BreakerOptions) {
    this.name = opts.name;
    this.threshold = Math.max(1, opts.failureThreshold ?? 3);
    this.openMs = Math.max(1000, opts.openMs ?? 30_000);
    this.now = opts.now ?? Date.now;
  }

  state(): BreakerState {
    if (this.openedAt === null) return 'closed';
    return this.now() - this.openedAt >= this.openMs ? 'half-open' : 'open';
  }

  /** Runs `fn` unless the breaker is open. Throws CircuitOpenError when it refuses; otherwise whatever `fn` throws. */
  async run<T>(fn: () => Promise<T>): Promise<T> {
    const state = this.state();
    if (state === 'open' || (state === 'half-open' && this.trialInFlight)) {
      this.shortCircuitedTotal += 1;
      const retryIn = this.openedAt === null ? 0 : Math.max(0, this.openMs - (this.now() - this.openedAt));
      throw new CircuitOpenError(this.name, retryIn);
    }
    if (state === 'half-open') this.trialInFlight = true;
    try {
      const result = await fn();
      this.failures = 0;
      this.openedAt = null;
      this.lastSuccess = this.now();
      return result;
    } catch (err) {
      this.failures += 1;
      this.lastFailure = this.now();
      if (state === 'half-open' || this.failures >= this.threshold) this.openedAt = this.now();
      throw err;
    } finally {
      this.trialInFlight = false;
    }
  }

  snapshot(): BreakerSnapshot {
    return {
      name: this.name,
      state: this.state(),
      consecutiveFailures: this.failures,
      shortCircuited: this.shortCircuitedTotal,
      lastFailureAt: this.lastFailure === null ? null : new Date(this.lastFailure).toISOString(),
      lastSuccessAt: this.lastSuccess === null ? null : new Date(this.lastSuccess).toISOString(),
      retryAt: this.openedAt === null ? null : new Date(this.openedAt + this.openMs).toISOString(),
    };
  }
}
