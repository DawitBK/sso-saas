import rateLimit, { type Options, type RateLimitRequestHandler } from "express-rate-limit";
import { createRateLimitStore } from "./rateLimitStore.js";

/**
 * Every rate limiter in SSO is built here, so the failure behaviour is decided in one place.
 *
 * `passOnStoreError: true` is the point. When REDIS_URL is set the counters live in Redis, and without this option a Redis outage
 * made every limited route (sign-in, token, the gateway) answer 500: SSO, the front door to everything, down because a rate-limit
 * counter could not be written. A rate limiter that cannot count must let the request through and say so in the log, not refuse
 * everyone. (Redis itself is configured to fail fast, infrastructure/redis.ts, so a down Redis costs no waiting either.)
 */
export function createLimiter(prefix: string, options: Partial<Options>): RateLimitRequestHandler {
  return rateLimit({
    standardHeaders: true,
    legacyHeaders: false,
    passOnStoreError: true,
    store: createRateLimitStore(prefix),
    ...options,
  });
}
