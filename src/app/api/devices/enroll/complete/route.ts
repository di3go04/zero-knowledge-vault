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
import { validateBase64Blob, IV_EXPECTED_BYTES, MAX_BLOB_BYTES } from "@/lib/crypto-server";
import { requireAuth } from "@/lib/auth-helper";

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

  const { enrollCode, wrappedPrivateKeyForDevice, wrappedPrivateKeyIv } = body ?? {};

  if (typeof enrollCode !== "string" || !/^\d{6}$/.test(enrollCode)) {
    return NextResponse.json({ error: "enrollCode debe ser 6 dígitos" }, { status: 400 });
  }
  if (!validateBase64Blob(wrappedPrivateKeyForDevice, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `wrappedPrivateKeyForDevice debe ser base64 ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(wrappedPrivateKeyIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `wrappedPrivateKeyIv debe ser base64 de ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }

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

  // Completar el enrollment: guardar wrappedPrivateKey + limpiar código
  await db.device.update({
    where: { id: device.id },
    data: {
      wrappedPrivateKeyForDevice,
      wrappedPrivateKeyIv,
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
