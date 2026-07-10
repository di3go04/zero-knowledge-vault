/**
 * GET /api/users/list
 *
 * Devuelve la lista de usuarios registrados (id, email, name, fingerprint).
 *
 * MEJORA Ciclo 2: usa Authorization: Bearer en lugar de x-user-id.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest) {
  const auth = requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const users = await db.user.findMany({
    where: { id: { not: userId } },
    select: {
      id: true,
      email: true,
      name: true,
      keyMaterial: { select: { publicKeyFingerprint: true } },
    },
    orderBy: { email: "asc" },
  });

  return NextResponse.json({
    users: users.map((u) => ({
      id: u.id,
      email: u.email,
      name: u.name,
      publicKeyFingerprint: u.keyMaterial?.publicKeyFingerprint ?? null,
    })),
  });
}
