/**
 * auth-helper.ts — Helpers compartidos para endpoints autenticados.
 */
import { NextRequest, NextResponse } from "next/server";
import { extractUserIdFromAuth } from "./session-token";

/**
 * Extrae el userId autenticado del header Authorization.
 * Verifica firma HMAC + blacklist (Redis o Map in-memory).
 *
 * ASYNC: la verificación de blacklist requiere I/O (Redis).
 */
export async function requireAuth(
  req: NextRequest,
): Promise<
  | { ok: true; userId: string }
  | { ok: false; response: NextResponse }
> {
  const userId = await extractUserIdFromAuth(req.headers.get("authorization"));
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
