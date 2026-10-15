import { RedisStore } from "rate-limit-redis";
import { redisClient } from "./redis.js";

/**
 * Returns a shared Redis-backed store when REDIS_URL is configured, or
 * `undefined` (express-rate-limit's own in-memory default) otherwise — the
 * same pattern GMS already uses (shared/middleware/rateLimiter.ts's
 * createStore). Every call site below stays functionally identical to
 * today until REDIS_URL is actually set.
 */
export const createRateLimitStore = (prefix: string) => {
  if (!redisClient) return undefined;
  const client = redisClient;
  return new RedisStore({
    // @ts-expect-error - ioredis's call() signature vs. rate-limit-redis's expected sendCommand type (same known mismatch GMS's createStore() suppresses)
    sendCommand: (...args: string[]) => client.call(...args),
    prefix: `sso-rl:${prefix}:`,
  });
};
