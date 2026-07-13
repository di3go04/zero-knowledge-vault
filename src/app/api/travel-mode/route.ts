import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { enableTravelMode, disableTravelMode } = await import("@/lib/travel-mode");
  const body = await req.json();
  const action = body.action;

  if (action === "enable") {
    const result = enableTravelMode(auth.userId);
    return NextResponse.json(result);
  } else if (action === "disable") {
    const result = disableTravelMode(auth.userId);
    return NextResponse.json(result);
  }
  return NextResponse.json({ error: "Invalid action" }, { status: 400 });
}
