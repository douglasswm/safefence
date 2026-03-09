/**
 * Redis-backed sliding window rate limiter using sorted sets.
 */

import type { MiddlewareHandler } from "hono";
import type { Redis } from "ioredis";

export interface RateLimitOptions {
  /** Time window in milliseconds */
  windowMs: number;
  /** Maximum requests per window */
  max: number;
  /** Redis key prefix (e.g. "rl:sync") */
  keyPrefix: string;
}

export function rateLimiter(redis: Redis, opts: RateLimitOptions): MiddlewareHandler {
  return async (c, next) => {
    const identifier =
      c.get("orgId") ??
      c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ??
      "unknown";

    const key = `${opts.keyPrefix}:${identifier}`;
    const now = Date.now();
    const windowStart = now - opts.windowMs;

    const pipeline = redis.pipeline();
    pipeline.zremrangebyscore(key, 0, windowStart);
    pipeline.zcard(key);
    const results = await pipeline.exec();

    const count = (results?.[1]?.[1] as number) ?? 0;

    if (count >= opts.max) {
      const resetAt = now + opts.windowMs;
      c.header("X-RateLimit-Limit", String(opts.max));
      c.header("X-RateLimit-Remaining", "0");
      c.header("X-RateLimit-Reset", String(Math.ceil(resetAt / 1000)));
      c.header("Retry-After", String(Math.ceil(opts.windowMs / 1000)));
      return c.json({ error: "Too many requests" }, 429);
    }

    // Add current request
    await redis.zadd(key, now, `${now}:${Math.random().toString(36).slice(2)}`);
    await redis.expire(key, Math.ceil(opts.windowMs / 1000));

    c.header("X-RateLimit-Limit", String(opts.max));
    c.header("X-RateLimit-Remaining", String(opts.max - count - 1));
    c.header("X-RateLimit-Reset", String(Math.ceil((now + opts.windowMs) / 1000)));

    await next();
  };
}
