/**
 * =====================================================================
 * csrf.ts — CSRF protection con doble cookie pattern.
 * =====================================================================
 *
 *
 * Flujo:
 *   1. El cliente pide un CSRF token a GET /api/auth/csrf
 *   2. El servidor setea una cookie httpOnly con el token
 *   3. El cliente envía el token en el header X-CSRF-Token
 *   4. El servidor compara cookie vs header
 *
 * Para endpoints que usan Bearer token (autenticados), el CSRF ya está
 * mitigado porque el atacante no puede leer el Bearer token. Pero para
 * endpoints públicos (register, login), añadimos esta capa extra.
 * =====================================================================
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

const CSRF_COOKIE_NAME = "zk-csrf";
const CSRF_HEADER_NAME = "x-csrf-token";

/**
 * Genera un CSRF token aleatorio (32 bytes hex).
 */
export function generateCsrfToken(): string {
  return randomBytes(32).toString("hex");
}

/**
 * Setea la cookie CSRF en la respuesta.
 */
export function setCsrfCookie(response: NextResponse, token: string): NextResponse {
  response.cookies.set(CSRF_COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 60 * 60, // 1 hora
  });
  return response;
}

/**
 * Verifica que el header X-CSRF-Token coincide con la cookie.
 * Usa timingSafeEqual para prevenir timing attacks.
 */
export function verifyCsrf(req: NextRequest): boolean {
  const cookieToken = req.cookies.get(CSRF_COOKIE_NAME)?.value;
  const headerToken = req.headers.get(CSRF_HEADER_NAME);

  if (!cookieToken || !headerToken) return false;
  if (cookieToken.length !== headerToken.length) return false;

  try {
    return timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken));
  } catch {
    return false;
  }
}

export { CSRF_COOKIE_NAME, CSRF_HEADER_NAME };
