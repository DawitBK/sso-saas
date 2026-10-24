import { RedisStore } from "rate-limit-redis";
import { redisClient } from "./redis.js";

/** How long the store's start-up script load waits for the connection to open. */
const STARTUP_WAIT_MS = 5000;

interface WaitableClient {
  status: string;
  call(...args: string[]): Promise<unknown>;
  once(event: "ready", listener: () => void): unknown;
  off(event: "ready", listener: () => void): unknown;
}

/**
 * rate-limit-redis loads its Lua scripts the moment the store is built, which is at import time, before the connection is open. The client
 * runs with the offline queue off (a rate limit must fail fast, not stall a sign-in), so that first command was refused with "Stream isn't
 * writeable", and the refusal was an unhandled rejection that stopped the process. Only that script load waits (bounded) for the connection;
 * every command a request sends still fails at once when Redis is not there.
 */
export function sendCommandWhenReady(client: WaitableClient, args: string[]): Promise<unknown> {
  const isScriptLoad = args[0]?.toUpperCase() === "SCRIPT";
  if (!isScriptLoad || client.status === "ready") return client.call(...args);
  return new Promise<void>((resolve, reject) => {
    const onReady = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      client.off("ready", onReady);
      reject(new Error("Redis did not become ready in time for the rate-limit scripts"));
    }, STARTUP_WAIT_MS);
    client.once("ready", onReady);
  }).then(() => client.call(...args));
}

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
    sendCommand: (...args: string[]) => sendCommandWhenReady(client as unknown as WaitableClient, args),
    prefix: `sso-rl:${prefix}:`,
  });
};
