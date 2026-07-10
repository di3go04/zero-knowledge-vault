/**
 * DELETE /api/secrets/[id]
 *
 * Borra un secreto. Solo el owner puede borrarlo. El borrado es en
 * cascada: todas las SecretKeyShare asociadas se borran automáticamente
 * (definido en el schema Prisma con onDelete: Cascade).
 *
 * Esto es CRÍTICO para el ciclo de vida de un secreto:
 *   - Si una credencial se compromete, el owner puede "destruirla"
 *     del lado del servidor.
 *   - Las wrappedKeys compartidas con otros usuarios también se borran,
 *     revocando efectivamente el acceso de todos los destinatarios.
 *
 * NOTA: Esto NO revoca acceso a destinatarios que YA descifraron el
 * secreto y lo guardaron localmente. Zero-Knowledge significa que el
 * servidor no puede garantizar la destrucción de copias descifradas.
 * Para mitigar, el owner debería rotar la credencial ANTES de borrar.
 *
 * MEJORA Ciclo 2.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id: secretId } = await params;
  if (!secretId) {
    return NextResponse.json({ error: "secretId requerido" }, { status: 400 });
  }

  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) {
    return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  }
  if (secret.ownerId !== userId) {
    // 404 en lugar de 403 para no revelar existencia del secreto
    return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  }

  // Borrar en cascada: Prisma eliminará automáticamente todas las
  // SecretKeyShare asociadas gracias a onDelete: Cascade.
  await db.secret.delete({ where: { id: secretId } });

  return NextResponse.json({
    secretId,
    deleted: true,
    note: "Secreto y todas sus shares eliminados. Recuerda: copias descifradas localmente por destinatarios previos NO pueden ser revocadas.",
  });
}
