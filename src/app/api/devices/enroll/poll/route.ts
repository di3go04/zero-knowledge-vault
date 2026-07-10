/**
 * POST /api/devices/enroll/poll
 *
 * Dispositivo NUEVO (B) hace poll para saber si su enrollment fue
 * completado por el dispositivo A. Si fue completado, devuelve la
 * wrappedPrivateKey para que B la desenvuelva con su ECDH privateKey.
 *
 * Body:
 *   { deviceId, publicKeyECDH (JWK) — para re-verificar identidad }
 *
 * El servidor NO requiere autenticación (el dispositivo B aún no tiene
 * sesión). En su lugar, valida que el deviceId existe y que el
 * enrollment fue completado (wrappedPrivateKeyForDevice no vacío).
 *
 * Adicionalmente, el dispositivo B debe enviar prueba de posesión de
 * su ECDH privateKey firmando un challenge. Por simplicidad en esta
 * demo, confiamos en que el deviceId + ECDH publicKey coinciden.
 * En producción se debe implementar un challenge-response ECDH.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { deviceId } = body ?? {};
  if (typeof deviceId !== "string" || !deviceId) {
    return NextResponse.json({ error: "deviceId requerido" }, { status: 400 });
  }

  const device = await db.device.findUnique({ where: { id: deviceId } });
  if (!device) {
    return NextResponse.json({ error: "Dispositivo no encontrado" }, { status: 404 });
  }

  // Verificar que el enrollment fue completado
  if (!device.wrappedPrivateKeyForDevice || device.wrappedPrivateKeyIv === "") {
    return NextResponse.json({
      enrolled: false,
      message: "El enrollment aún no ha sido completado. Espera a que el dispositivo autorizado introduzca el código.",
    });
  }

  // Verificar que no esté revocado
  if (device.revokedAt) {
    return NextResponse.json({ error: "Dispositivo revocado" }, { status: 403 });
  }

  // Actualizar lastSeenAt
  await db.device.update({
    where: { id: deviceId },
    data: { lastSeenAt: new Date() },
  });

  // Devolver la wrappedPrivateKey para que el dispositivo B la desenvuelva
  return NextResponse.json({
    enrolled: true,
    deviceId: device.id,
    deviceName: device.deviceName,
    wrappedPrivateKeyForDevice: device.wrappedPrivateKeyForDevice,
    wrappedPrivateKeyIv: device.wrappedPrivateKeyIv,
    publicKeyECDH: JSON.parse(device.publicKeyECDH),
    note: "Desenvuelve la privateKey RSA con tu ECDH privateKey usando ECDH(shared, peerPublic).",
  });
}
