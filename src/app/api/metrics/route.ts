import { NextResponse } from "next/server";
import { getMetrics, incrementRequestCount } from "@/lib/metrics-store";
import { logger } from "@/lib/logger";

export const dynamic = "force-dynamic";

export async function GET() {
  const metrics = await getMetrics();

  return NextResponse.json({
    ...metrics,
    unit: "cumulative",
    timestamp: new Date().toISOString(),
  });
}

export async function POST(request: Request) {
  const authHeader = request.headers.get("authorization");
  const adminSecret = process.env.METRICS_ADMIN_SECRET;
  if (adminSecret) {
    if (authHeader !== `Bearer ${adminSecret}`) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
  }

  try {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const action = body.action as string | undefined;
    const userId = body.userId as string | undefined;

    if (action === "record_activity" && userId) {
      const { recordActiveConnection } = await import("@/lib/metrics-store");
      await recordActiveConnection(userId);
    }

    const count = await incrementRequestCount();

    return NextResponse.json({ ok: true, request_count: count });
  } catch (err) {
    logger.error({ err }, "metrics POST failed");
    return NextResponse.json({ error: "failed" }, { status: 500 });
  }
}
