/**
 * GET /api/health — Healthcheck endpoint for production monitoring.
 *
 * Returns:
 *   {
 *     status: "healthy" | "degraded",
 *     version: "1.0.0",
 *     checks: {
 *       database: "ok" | "error",
 *       redis: "ok" | "error" | "not_configured"
 *     },
 *     timestamp: ISO-8601
 *   }
 *
 * Status code: 200 if healthy, 503 if degraded.
 */
import { NextResponse } from "next/server";
import { db } from "@/lib/db";
import { logger } from "@/lib/logger";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const packageJsonPath = join(__dirname, "../../../../package.json");

function getVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(packageJsonPath, "utf-8"));
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

export async function GET() {
  const checks: Record<string, string> = {};

  // Check database (Prisma)
  try {
    await db.$queryRaw`SELECT 1`;
    checks.database = "ok";
  } catch (err) {
    logger.error({ err }, "health check: database failed");
    checks.database = "error";
  }

  // Check Redis (optional — only if REDIS_URL is set)
  if (process.env.REDIS_URL) {
    try {
      const { default: Redis } = await import("ioredis");
      const redis = new Redis(process.env.REDIS_URL, {
        connectTimeout: 1000,
        maxRetriesPerRequest: 1,
      });
      await redis.ping();
      await redis.quit();
      checks.redis = "ok";
    } catch (err) {
      logger.error({ err }, "health check: redis failed");
      checks.redis = "error";
    }
  } else {
    checks.redis = "not_configured";
  }

  const allOk = Object.values(checks).every(
    (v) => v === "ok" || v === "not_configured"
  );

  return NextResponse.json(
    {
      status: allOk ? "healthy" : "degraded",
      version: getVersion(),
      checks,
      timestamp: new Date().toISOString(),
    },
    { status: allOk ? 200 : 503 }
  );
}
