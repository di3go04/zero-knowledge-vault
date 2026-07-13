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
import { requireAuth } from "@/lib/auth-helper";
import { recoverySetupSchema, validatePayload } from "@/lib/validation-schemas";

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

  const validation = validatePayload(recoverySetupSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const {
    recoverySalt,
    recoveryIterations,
    encryptedPrivateKeyForRecovery,
    recoveryIv,
  } = validation.data;

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
