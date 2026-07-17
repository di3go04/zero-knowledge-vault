import { NextResponse } from "next/server";
import { PrismaClient } from "@prisma/client";
import { incrementMetric } from "@/app/api/metrics/route";

const prisma = new PrismaClient();

export async function GET() {
  incrementMetric("api_request");

  const checks = {
    status: "ok",
    version: "0.2.0",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    checks: {
      database: false,
      redis: false,
    },
  };

  try {
    await prisma.$queryRaw`SELECT 1`;
    checks.checks.database = true;
  } catch {
    checks.checks.database = false;
    checks.status = "degraded";
  }

  const redisUrl = process.env.REDIS_URL;
  checks.checks.redis = !!redisUrl;

  const statusCode = checks.status === "ok" ? 200 : 503;
  return NextResponse.json(checks, { status: statusCode });
}
