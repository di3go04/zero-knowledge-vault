import { NextResponse } from "next/server";
import { checkAllSwitches } from "@/lib/dead-mans-switch";
import { logger } from "@/lib/logger";

export const dynamic = "force-dynamic";
export const maxDuration = 60;

export async function GET(request: Request) {
  const authHeader = request.headers.get("authorization");

  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const expected = `Bearer ${cronSecret}`;
    if (authHeader !== expected) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
  }

  try {
    const results = await checkAllSwitches();
    const triggered = results.filter((r) => r.triggered);

    logger.info({ total: results.length, triggered: triggered.length }, "dead man switch cron completed");

    return NextResponse.json({
      ok: true,
      checked: results.length,
      triggered: triggered.length,
      details: results,
    });
  } catch (err) {
    logger.error({ err }, "dead man switch cron failed");
    return NextResponse.json({ error: "cron failed" }, { status: 500 });
  }
}
