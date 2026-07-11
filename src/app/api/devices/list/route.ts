/**
 * GET /api/devices/list
 *
 * Lista los dispositivos autorizados del usuario autenticado.
 *
 * MEJORA Fase 2 — Multi-Device Sync.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const devices = await db.device.findMany({
    where: { userId, revokedAt: null },
    select: {
      id: true,
      deviceName: true,
      publicKeyECDHFingerprint: true,
      enrolledAt: true,
      lastSeenAt: true,
    },
    orderBy: { enrolledAt: "desc" },
  });

  return NextResponse.json({ devices });
}
