/**
 * DELETE /api/devices/[id]
 *
 * Revoca un dispositivo. Solo el owner puede revocar sus propios
 * dispositivos. Esto es crítico para offboarding de dispositivos
 * perdidos o robados.
 *
 * Marca revokedAt = now() en lugar de borrar el registro, para
 * mantener auditoría. El dispositivo revocado ya no puede hacer poll
 * ni descifrar nuevas peticiones.
 *
 * Si el dispositivo ya descifró la privateKey RSA y la guardó
 * localmente, la revocación NO puede borrar esa copia. En ese caso,
 * el usuario debe rotar su contraseña maestra (lo que re-cifra la
 * privateKey, invalidando la copia del dispositivo revocado).
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id: deviceId } = await params;
  if (!deviceId) {
    return NextResponse.json({ error: "deviceId requerido" }, { status: 400 });
  }

  const device = await db.device.findUnique({ where: { id: deviceId } });
  if (!device) {
    return NextResponse.json({ error: "Dispositivo no encontrado" }, { status: 404 });
  }
  if (device.userId !== userId) {
    return NextResponse.json({ error: "Dispositivo no encontrado" }, { status: 404 });
  }
  if (device.revokedAt) {
    return NextResponse.json({ error: "Dispositivo ya revocado" }, { status: 400 });
  }

  await db.device.update({
    where: { id: deviceId },
    data: { revokedAt: new Date() },
  });

  return NextResponse.json({
    deviceId,
    revoked: true,
    note: "Dispositivo revocado. Si tenía copia local de la privateKey, rota tu contraseña maestra para invalidarla.",
  });
}
