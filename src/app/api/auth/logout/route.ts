/**
 * POST /api/auth/logout
 *
 * Logout server-side real. Inserta el jti del token en la blacklist
 * (Redis en producción, Map in-memory en dev) con TTL = tiempo restante
 * de expiración. Esto invalida el token inmediatamente en el servidor.
 *
 * MEJORA Fase 2 — logout server-side real con Redis blacklist.
 *
 * Requiere autenticación (Bearer token). Si el token ya expiró o está
 * en blacklist, devuelve 200 OK (idempotente).
 */
import { NextRequest, NextResponse } from "next/server";
import { revokeSessionToken, verifySessionToken } from "@/lib/session-token";

export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("authorization");
  if (!authHeader) {
    return NextResponse.json({ loggedOut: true, note: "Sin token — nada que revocar" });
  }

  // Verificar que el token sea válido (no expirado, firma correcta)
  const match = /^Bearer\s+(.+)$/i.exec(authHeader);
  if (!match) {
    return NextResponse.json({ loggedOut: true, note: "Token malformado" });
  }

  const payload = verifySessionToken(match[1]);
  if (!payload) {
    // Token inválido o expirado — ya está efectivamente revocado
    return NextResponse.json({ loggedOut: true, note: "Token ya expirado o inválido" });
  }

  // Insertar jti en blacklist con TTL = exp - now
  const revoked = await revokeSessionToken(match[1]);
  if (!revoked) {
    return NextResponse.json(
      { error: "No se pudo revocar el token" },
      { status: 500 },
    );
  }

  return NextResponse.json({
    loggedOut: true,
    jti: payload.jti,
    ttlSeconds: payload.exp - Math.floor(Date.now() / 1000),
    note: "Token revocado en el servidor. Las peticiones futuras con este token serán rechazadas.",
  });
}
