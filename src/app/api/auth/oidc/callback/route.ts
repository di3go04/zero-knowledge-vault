/**
 * GET /api/auth/oidc/callback — Callback de Google OIDC.
 *
 *
 * Flujo:
 *   1. Verifica state contra cookie
 *   2. Intercambia code por id_token con Google
 *   3. Extrae email del id_token
 *   4. Busca usuario por email en BD
 *   5. Si existe → emite sessionToken + redirige a /?oidc=1
 *   6. Si no existe → redirige a /?oidc=error (debe registrar primero)
 *
 * NOTA: OIDC NO puede descifrar la privateKey. El usuario debe introducir
 * su contraseña maestra después del OIDC para descifrar localmente.
 * OIDC solo autentica que el usuario es quien dice ser.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { issueSessionToken } from "@/lib/session-token";

const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

export async function GET(req: NextRequest) {
  const code = req.nextUrl.searchParams.get("code");
  const state = req.nextUrl.searchParams.get("state");
  const cookieState = req.cookies.get("oidc_state")?.value;
  const codeVerifier = req.cookies.get("oidc_verifier")?.value;

  if (!code || !state || state !== cookieState) {
    return NextResponse.redirect(new URL("/?oidc=error&reason=state", req.url));
  }

  const clientId = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const redirectUri = process.env.OIDC_REDIRECT_URI || "http://localhost:3000/api/auth/oidc/callback";

  if (!clientId || !clientSecret) {
    return NextResponse.redirect(new URL("/?oidc=error&reason=config", req.url));
  }

  // Intercambiar code por tokens
  const tokenRes = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: codeVerifier!,
    }),
  });

  if (!tokenRes.ok) {
    return NextResponse.redirect(new URL("/?oidc=error&reason=token", req.url));
  }

  const tokenData = await tokenRes.json();

  // Decodificar id_token (JWT) para extraer email
  const idToken = tokenData.id_token;
  const payload = JSON.parse(
    Buffer.from(idToken.split(".")[1], "base64").toString("utf-8"),
  );
  const email = payload.email as string;

  if (!email) {
    return NextResponse.redirect(new URL("/?oidc=error&reason=noemail", req.url));
  }

  // Buscar usuario por email
  const user = await db.user.findUnique({
    where: { email: email.toLowerCase() },
    include: { keyMaterial: true },
  });

  if (!user || !user.keyMaterial) {
    return NextResponse.redirect(new URL("/?oidc=error&reason=nouser", req.url));
  }

  // Emitir sessionToken
  const sessionToken = issueSessionToken(user.id);

  // Limpiar cookies OIDC
  const response = NextResponse.redirect(new URL(`/?oidc=1&token=${sessionToken}&email=${encodeURIComponent(email)}`, req.url));
  response.cookies.delete("oidc_state");
  response.cookies.delete("oidc_verifier");

  return response;
}
