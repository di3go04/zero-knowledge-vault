import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { cleanupExpiredResources } from "@/lib/collab/cleanup";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const result = await cleanupExpiredResources();

  return NextResponse.json({
    cleaned: true,
    ...result,
    message: "Recursos expirados limpiados",
  });
}
