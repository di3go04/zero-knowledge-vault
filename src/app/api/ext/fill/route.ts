/**
 * GET /api/ext/fill?url=xxx — API para extensión de navegador.
 *
 *
 * La extensión del navegador usa este endpoint para:
 *   1. Obtener la lista de secretos del usuario autenticado
 *   2. Buscar por dominio de la URL actual
 *   3. Devolver los secretos cifrados para que la extensión los descifre
 *
 * La extensión debe tener el sessionToken del login.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const shares = await db.secretKeyShare.findMany({
    where: { recipientId: userId },
    include: {
      secret: {
        include: {
          owner: { select: { email: true } },
        },
      },
    },
    orderBy: { createdAt: "desc" },
    take: 100,
  });

  // Devolver formato simplificado para extensión
  const items = shares.map((s) => ({
    id: s.secret.id,
    encryptedTitle: s.secret.encryptedTitle,
    titleIv: s.secret.titleIv,
    encryptedData: s.secret.encryptedData,
    dataIv: s.secret.dataIv,
    wrappedKey: s.wrappedSymmetricKey,
    owner: s.secret.owner.email,
  }));

  return NextResponse.json({ items });
}
