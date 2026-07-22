/**
 * Middleware de seguridad — CSP con nonces + headers de seguridad.
 *
 * Genera un nonce criptográfico por request que se inyecta en la
 * Content-Security-Policy. El nonce está disponible vía header
 * x-nonce para que server components puedan aplicarlo a <script> tags.
 *
 * Content-Security-Policy usa 'strict-dynamic' + nonce, lo que
 * permite que Next.js cargue dinámicamente chunks de JS mientras
 * bloquea inline scripts sin nonce. 'unsafe-inline' se mantiene como
 * fallback para navegadores que no soportan strict-dynamic (CSP Level 2).
 */
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export function middleware(request: NextRequest) {
  const nonce = crypto.randomUUID();

  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-inline'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "connect-src 'self' https://api.github.com",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "manifest-src 'self'",
    "worker-src 'self' blob:",
  ].join("; ");

  const response = NextResponse.next();

  response.headers.set("x-nonce", nonce);
  response.headers.set("Content-Security-Policy", csp);
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("X-Frame-Options", "DENY");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
  );
  response.headers.set(
    "Cross-Origin-Opener-Policy",
    "same-origin",
  );
  response.headers.set(
    "Cross-Origin-Embedder-Policy",
    "require-corp",
  );
  response.headers.set(
    "Cross-Origin-Resource-Policy",
    "same-origin",
  );

  return response;
}

export const config = {
  matcher: [
    // Excluir recursos estáticos y APIs del CSP (ya tienen sus propios headers)
    "/((?!api/|_next/static|_next/image|favicon.ico|logo.svg).*)",
  ],
};
