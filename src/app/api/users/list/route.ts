/**
 * GET /api/users/list
 *
 * Devuelve la lista de usuarios registrados (id, email, name) — SIN
 * incluir llaves privadas ni material sensible. Útil para poblar el
 * selector de destinatarios al compartir un secreto.
 *
 * Header: x-user-id (debe estar autenticado)
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const userId = req.headers.get("x-user-id");
  if (!userId) {
    return NextResponse.json({ error: "No autenticado" }, { status: 401 });
  }

  const users = await db.user.findMany({
    where: { id: { not: userId } },
    select: { id: true, email: true, name: true },
    orderBy: { email: "asc" },
  });

  return NextResponse.json({ users });
}
