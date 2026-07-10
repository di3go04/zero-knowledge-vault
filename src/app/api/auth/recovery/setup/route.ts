/**
 * POST /api/auth/recovery/setup
 *
 * Configura o actualiza el backup de recuperación. Requiere autenticación.
 *
 * El cliente envía:
 *   { recoverySalt, recoveryIterations, encryptedPrivateKeyForRecovery, recoveryIv }
 *
 * El servidor almacena estos blobs sin ver su contenido. Solo verifica
 * que sean base64 con tamaños plausibles.
 *
 * Tras setup, recoveryEnabled = true. El usuario puede usar el flujo
 * /recovery/recover si olvida su contraseña maestra.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  IV_EXPECTED_BYTES,
  MAX_BLOB_BYTES,
  SALT_MAX_BYTES,
  SALT_MIN_BYTES,
  validateBase64Blob,
} from "@/lib/crypto-server";
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

  const {
    recoverySalt,
    recoveryIterations,
    encryptedPrivateKeyForRecovery,
    recoveryIv,
  } = body ?? {};

  if (!validateBase64Blob(recoverySalt, SALT_MIN_BYTES, SALT_MAX_BYTES)) {
    return NextResponse.json(
      { error: `recoverySalt debe ser base64 de ${SALT_MIN_BYTES}-${SALT_MAX_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (
    typeof recoveryIterations !== "number" ||
    recoveryIterations < 100_000 ||
    recoveryIterations > 10_000_000
  ) {
    return NextResponse.json(
      { error: "recoveryIterations debe estar entre 100.000 y 10.000.000" },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(encryptedPrivateKeyForRecovery, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `encryptedPrivateKeyForRecovery debe ser base64 ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(recoveryIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `recoveryIv debe ser base64 de ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }

  // Verificar que el usuario existe
  const user = await db.user.findUnique({
    where: { id: userId },
    include: { keyMaterial: true },
  });
  if (!user || !user.keyMaterial) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  await db.userKeyMaterial.update({
    where: { userId },
    data: {
      recoverySalt,
      recoveryIterations,
      encryptedPrivateKeyForRecovery,
      recoveryIv,
      recoveryEnabled: true,
    },
  });

  return NextResponse.json({
    recoveryEnabled: true,
    note: "Backup de recuperación configurado. Guarda tus 24 palabras en un lugar seguro — el servidor no las tiene.",
  });
}
