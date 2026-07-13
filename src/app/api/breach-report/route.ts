import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { generateBreachReport } = await import("@/lib/breach-report");
  const report = await generateBreachReport("user@example.com");
  return NextResponse.json(report);
}
