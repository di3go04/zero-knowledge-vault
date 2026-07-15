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
import { parsePagination } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const [devices, total] = await Promise.all([
    db.device.findMany({
      where: { userId, revokedAt: null },
      select: {
        id: true,
        deviceName: true,
        publicKeyECDHFingerprint: true,
        enrolledAt: true,
        lastSeenAt: true,
      },
      orderBy: { enrolledAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.device.count({
      where: { userId, revokedAt: null },
    }),
  ]);

  return NextResponse.json({
    devices,
    pagination: {
      offset,
      limit,
      total,
      hasMore: offset + limit < total,
    },
  });
}
