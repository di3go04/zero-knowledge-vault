/**
 * POST /api/devices/enroll/complete
 *
 * Dispositivo AUTENTICADO (A) llama a este endpoint para completar el
 * enrollment de un dispositivo nuevo (B).
 *
 * Body:
 *   { enrollCode, wrappedPrivateKeyForDevice (base64), wrappedPrivateKeyIv (base64) }
 *
 * El servidor:
 *   1. Verifica la autenticación del dispositivo A (Bearer token).
 *   2. Busca el Device pendiente por enrollCode (debe estar no expirado).
 *   3. Verifica que el Device pertenece al MISMO usuario que A.
 *   4. Actualiza wrappedPrivateKeyForDevice + wrappedPrivateKeyIv.
 *   5. Limpia enrollCode (ya no se puede reusar).
 *
 * CRÍTICO: el servidor no valida el contenido de wrappedPrivateKeyForDevice
 * — es un blob opaco. Solo verifica que sea base64 de tamaño plausible.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { enrollCompleteSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(enrollCompleteSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { enrollCode, wrappedPrivateKeyForDevice, wrappedPrivateKeyIv, enrollerPublicKeyECDH } = validation.data;

  // Buscar Device pendiente por enrollCode
  const device = await db.device.findFirst({
    where: {
      enrollCode,
      enrollCodeExpiresAt: { gt: new Date() },
      revokedAt: null,
    },
  });

  if (!device) {
    return NextResponse.json(
      { error: "Código de enrollment inválido o expirado" },
      { status: 404 },
    );
  }

  // Verificar que el dispositivo A (autenticado) pertenece al mismo usuario
  // que el dispositivo B (el que inició el enrollment)
  if (device.userId !== userId) {
    return NextResponse.json(
      { error: "El código de enrollment no pertenece a tu cuenta" },
      { status: 403 },
    );
  }

  // Completar el enrollment: guardar wrappedPrivateKey + publicKey efímera de A + limpiar código
  await db.device.update({
    where: { id: device.id },
    data: {
      wrappedPrivateKeyForDevice,
      wrappedPrivateKeyIv,
      enrollerPublicKeyECDH: JSON.stringify(enrollerPublicKeyECDH),
      enrollCode: null,
      enrollCodeExpiresAt: null,
      lastSeenAt: new Date(),
    },
  });

  return NextResponse.json({
    deviceId: device.id,
    deviceName: device.deviceName,
    enrolled: true,
    note: "Dispositivo autorizado. El nuevo dispositivo ya puede hacer poll y obtener su privateKey.",
  });
}
