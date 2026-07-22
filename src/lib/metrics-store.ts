import { db } from "./db";
import { logger } from "./logger";

let redisClient: import("ioredis").Redis | null = null;
let redisAttempted = false;

async function getRedis(): Promise<import("ioredis").Redis | null> {
  if (redisClient) return redisClient;
  if (redisAttempted) return null;
  redisAttempted = true;

  const url = process.env.REDIS_URL;
  if (!url) return null;

  try {
    const { default: Redis } = await import("ioredis");
    redisClient = new Redis(url, { connectTimeout: 2000, maxRetriesPerRequest: 1 });
    await redisClient.ping();
    logger.info("[metrics] Redis connected");
    return redisClient;
  } catch (err) {
    logger.warn({ err }, "[metrics] Redis unavailable, using DB fallback");
    return null;
  }
}

export async function incrementRequestCount(): Promise<number> {
  const redis = await getRedis();
  if (redis) {
    try {
      return await redis.incr("metrics:request_count");
    } catch {
      logger.warn("[metrics] Redis INCR failed, falling back to DB");
    }
  }

  const metric = await db.metric.upsert({
    where: { name: "request_count" },
    update: { value: { increment: 1 } },
    create: { name: "request_count", value: 1 },
  });
  return metric.value;
}

export async function getRequestCount(): Promise<number> {
  const redis = await getRedis();
  if (redis) {
    try {
      const v = await redis.get("metrics:request_count");
      if (v !== null) return parseInt(v, 10);
    } catch {
      /* fallback to DB */
    }
  }

  const metric = await db.metric.findUnique({ where: { name: "request_count" } });
  return metric?.value ?? 0;
}

export async function recordActiveConnection(userId: string): Promise<void> {
  const redis = await getRedis();
  if (redis) {
    try {
      const key = `metrics:active_user:${userId}`;
      await redis.set(key, Date.now().toString(), "EX", 300);
      return;
    } catch {
      /* skip */
    }
  }
}

export async function getActiveConnections(): Promise<number | null> {
  const redis = await getRedis();
  if (!redis) return null;

  try {
    const keys = await redis.keys("metrics:active_user:*");
    let count = 0;
    const now = Date.now();
    for (const key of keys) {
      const ts = await redis.get(key);
      if (ts && now - parseInt(ts, 10) < 300_000) count++;
      else await redis.del(key);
    }
    return count;
  } catch {
    return null;
  }
}

export async function getMetrics() {
  const [requestCount, activeConnections] = await Promise.all([
    getRequestCount(),
    getActiveConnections(),
  ]);

  return {
    request_count: requestCount,
    ...(activeConnections !== null ? { active_connections: activeConnections } : {}),
  };
}
