/**
 * auth-helper.ts — Helpers compartidos para endpoints autenticados.
 *
 * Si el middleware global (middleware.ts) ya verificó el token, lee el
 * userId del header x-authenticated-user-id sin hacer I/O redundante.
 * Si no está presente, verifica el token directamente (fallback).
 */
import { NextRequest, NextResponse } from "next/server";
import { extractUserIdFromAuth } from "./session-token";

export async function requireAuth(
  req: NextRequest,
): Promise<
  | { ok: true; userId: string }
  | { ok: false; response: NextResponse }
> {
  const middlewareUserId = req.headers.get("x-authenticated-user-id");
  if (middlewareUserId) {
    return { ok: true, userId: middlewareUserId };
  }

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
