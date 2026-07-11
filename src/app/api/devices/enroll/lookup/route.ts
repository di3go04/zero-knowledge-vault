/**
 * GET /api/devices/enroll/lookup?code=123456
 *
 * Busca un dispositivo pendiente por su enrollCode. Lo usa el
 * Dispositivo A (autenticado) para obtener la publicKey ECDH del
 * Dispositivo B antes de completar el enrollment.
 *
 * Requiere autenticación (Dispositivo A). Verifica que el dispositivo
 * pertenece al mismo usuario.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const code = req.nextUrl.searchParams.get("code");
  if (!code || !/^\d{6}$/.test(code)) {
    return NextResponse.json({ error: "code debe ser 6 dígitos" }, { status: 400 });
  }

  const device = await db.device.findFirst({
    where: {
      enrollCode: code,
      enrollCodeExpiresAt: { gt: new Date() },
      revokedAt: null,
    },
  });

  if (!device) {
    return NextResponse.json(
      { error: "Código inválido, expirado o ya usado" },
      { status: 404 },
    );
  }

  // Verificar que el dispositivo pertenece al mismo usuario autenticado
  if (device.userId !== userId) {
    // 404 para no revelar existencia
    return NextResponse.json(
      { error: "Código inválido, expirado o ya usado" },
      { status: 404 },
    );
  }

  return NextResponse.json({
    deviceId: device.id,
    deviceName: device.deviceName,
    publicKeyECDH: JSON.parse(device.publicKeyECDH),
    publicKeyECDHFingerprint: device.publicKeyECDHFingerprint,
    enrollCodeExpiresAt: device.enrollCodeExpiresAt,
  });
}
