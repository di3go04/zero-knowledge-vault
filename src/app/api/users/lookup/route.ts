/**
 * GET /api/users/lookup?email=...
 *
 * Busca un usuario por email y devuelve SU ID + SU LLAVE PÚBLICA.
 * Esto es necesario para que un cliente pueda envolver (wrap) una
 * llave AES con la llave pública del destinatario antes de compartir.
 *
 * La llave pública ES pública por definición — exponerla no rompe
 * el modelo Zero-Knowledge.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const email = req.nextUrl.searchParams.get("email");
  if (!email) {
    return NextResponse.json({ error: "Parámetro 'email' requerido" }, { status: 400 });
  }

  const user = await db.user.findUnique({
    where: { email },
    include: { keyMaterial: true },
  });

  if (!user || !user.keyMaterial) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  return NextResponse.json({
    userId: user.id,
    email: user.email,
    name: user.name,
    publicKeyJwk: JSON.parse(user.keyMaterial.publicKeyJwk),
  });
}
