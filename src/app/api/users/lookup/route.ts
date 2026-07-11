/**
 * GET /api/users/lookup?email=...
 *
 * Busca un usuario por email y devuelve SU ID + SU LLAVE PÚBLICA + SU
 * FINGERPRINT. Esto es necesario para que un cliente pueda:
 *   1. envolver (wrap) una llave AES con la publicKey del destinatario
 *   2. verificar TOFU comparando la fingerprint recibida con la que el
 *      destinatario le comunicó fuera de banda
 *
 * La llave pública ES pública por definición — exponerla no rompe
 * el modelo Zero-Knowledge. La fingerprint es un hash de la publicKey,
 * también público por definición.
 *
 * MEJORA Ciclo 1 — Anti-enumeración:
 *   Si el email NO existe, devolvemos 404 con un mensaje genérico.
 *   No generamos decoy aquí porque la fingerprint debe ser verificable
 *   fuera de banda por el destinatario real, y un decoy rompería el
 *   TOFU. En su lugar, confiamos en rate-limiting (futuro ciclo) para
 *   mitigar la enumeración en este endpoint.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { queryEmailSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const validation = validatePayload(queryEmailSchema, {
    email: req.nextUrl.searchParams.get("email"),
  });
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const normalizedEmail = validation.data.email.toLowerCase().trim();

  const user = await db.user.findUnique({
    where: { email: normalizedEmail },
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
    publicKeyFingerprint: user.keyMaterial.publicKeyFingerprint,
  });
}
