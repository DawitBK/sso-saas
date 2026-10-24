import * as IORedis from "ioredis";
import { logger } from "../logging/logger.js";

// ioredis's CJS/ESM interop is ambiguous under this project's module
// resolution — same workaround DMS's infrastructure/cache/redis.ts already
// uses for the identical issue.
const RedisCtor = ((IORedis as any).default ?? IORedis) as new (
  url: string,
  options?: Record<string, unknown>,
) => IORedis.Redis;

/**
 * Entirely optional — SSO has no Redis dependency today (see
 * PLATFORM_ARCHITECTURE.md §9), and
 * this box is RAM-constrained (~10GB total, already running Postgres +
 * MySQL + MSSQL + Redis-for-DMS + ~10 Node processes).
 * Provisioning Redis specifically
 * for SSO is not being forced on anyone by this file: if REDIS_URL isn't
 * set, this returns null and every rate limiter below falls back to its
 * existing per-process in-memory store exactly as it does today — no new
 * dependency is actually required unless someone opts in.
 *
 * The reason to opt in eventually: SSO's rate limiters are per-process
 * in-memory, which silently divides the effective limit by instance count
 * the day SSO ever runs more than one process (its own main.ts comment
 * already flags this as "revisit if SSO ever runs more than one process").
 * This is that revisit, made available now rather than needed urgently.
 */
export const redisClient: IORedis.Redis | null = process.env.REDIS_URL
  ? new RedisCtor(process.env.REDIS_URL, {
      // Fail fast rather than hang requests if Redis is unreachable — this
      // is a rate-limit store, not a critical dependency; a slow/absent
      // Redis should degrade, not stall logins.
      maxRetriesPerRequest: 1,
      // With the offline queue on (the default) a command issued while Redis is down WAITS for the reconnect; off, it fails at once,
      // which rateLimiter.ts turns into "let the request through" instead of a stalled sign-in.
      enableOfflineQueue: false,
      connectTimeout: 2000,
      lazyConnect: false,
    })
  : null;

if (redisClient) {
  redisClient.on("error", (err: Error) => {
    logger.error({ err }, "Redis connection error (rate-limit store) — falling back to in-memory limiting for affected requests");
  });
  logger.info("REDIS_URL configured — rate limiters will use a shared Redis store");
} else {
  logger.warn("REDIS_URL not set — rate limiters use per-process in-memory stores (fine for a single instance; will not share limits across multiple SSO processes)");
}
