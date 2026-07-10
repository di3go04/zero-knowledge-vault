/**
 * auth-helper.ts — Helpers compartidos para endpoints autenticados.
 */
import { NextRequest, NextResponse } from "next/server";
import { extractUserIdFromAuth } from "./session-token";

/**
 * Extrae el userId autenticado del header Authorization.
 * Devuelve { userId } si el token es válido, o { response: 401 } si no.
 */
export function requireAuth(req: NextRequest):
  | { ok: true; userId: string }
  | { ok: false; response: NextResponse } {
  const userId = extractUserIdFromAuth(req.headers.get("authorization"));
  if (!userId) {
    return {
      ok: false,
      response: NextResponse.json(
        { error: "No autenticado. Proporciona un Authorization: Bearer <token> válido." },
        { status: 401 },
      ),
    };
  }
  return { ok: true, userId };
}
