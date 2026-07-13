/**
 * GET /api/secrets/[id]/versions — Lista el historial de versiones de un secreto.
 *
 *
 * Devuelve todas las versiones anteriores del secreto (cifradas).
 * El cliente puede descifrarlas con la misma llave AES del secreto actual.
 *
 * El servidor solo devuelve blobs cifrados — no ve el contenido.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { pathIdSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id } = await params;
  const idValidation = validatePayload(pathIdSchema, id);
  if (!idValidation.success) {
    return NextResponse.json({ error: idValidation.error }, { status: 400 });
  }
  const secretId = idValidation.data;

  // Verificar que el usuario tiene acceso al secreto
  const share = await db.secretKeyShare.findUnique({
    where: { secretId_recipientId: { secretId, recipientId: userId } },
  });
  if (!share) {
    return NextResponse.json({ error: "No tienes acceso a este secreto" }, { status: 403 });
  }

  const versions = await db.secretVersion.findMany({
    where: { secretId },
    orderBy: { version: "desc" },
    select: {
      id: true,
      encryptedData: true,
      dataIv: true,
      version: true,
      createdAt: true,
    },
  });

  return NextResponse.json({ versions });
}
