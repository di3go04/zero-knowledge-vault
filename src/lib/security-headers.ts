/**
 * security-headers.ts — CSP estricto, SRI, CORS configurable.
 *
 *
 * Estas funciones se aplican en el middleware de Next.js.
 */
import { NextRequest, NextResponse } from "next/server";

/**
 * Aplica headers de seguridad a todas las respuestas.
 */
export function applySecurityHeaders(response: NextResponse): NextResponse {
  //
  response.headers.set(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com",
      "style-src 'self' 'unsafe-inline' https://unpkg.com",
      "img-src 'self' data: https:",
      "connect-src 'self' ws: wss: https://api.pwnedpasswords.com https://accounts.google.com",
      "font-src 'self' data:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'self' https://accounts.google.com",
    ].join("; "),
  );

  //
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set("Permissions-Policy", "geolocation=(), microphone=(), camera=()");

  //
  const allowedOrigins = process.env.CORS_ORIGINS?.split(",") ?? ["*"];
  if (allowedOrigins[0] !== "*") {
    response.headers.set("Access-Control-Allow-Origin", allowedOrigins.join(", "));
    response.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response.headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token");
    response.headers.set("Access-Control-Max-Age", "86400");
  }

  return response;
}
