/**
 * GET /api/ws-token
 *
 * El cliente usa este token para conectar al WebSocket service.
 */
import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { issueSessionToken } from "@/lib/session-token";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  // Reusar el sistema de tokens HS256 para WS
  const wsToken = issueSessionToken(userId);

  return NextResponse.json({
    wsToken,
    wsUrl: "/?XTransformPort=3003",
  });
}
