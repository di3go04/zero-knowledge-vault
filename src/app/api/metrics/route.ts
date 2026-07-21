import { NextResponse } from "next/server";
import { getMetrics } from "@/lib/metrics-store";
export async function GET() {
  return new NextResponse(getMetrics(), { headers: { "Content-Type": "text/plain" } });
}
