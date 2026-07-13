/**
 * GET /api/auth/oidc/init — Inicia flujo OIDC con Google.
 *
 *
 * Variables de entorno necesarias:
 *   OIDC_CLIENT_ID — Google OAuth client ID
 *   OIDC_REDIRECT_URI — callback URL (ej: https://app.com/api/auth/oidc/callback)
 *
 * El flujo OIDC se inicia DESPUÉS de que el usuario ya tiene una cuenta
 * (con par RSA + masterKey). OIDC es solo para autenticación de sesión,
 * NO para derivación de llaves. El usuario debe haber registrado su cuenta
 * primero con contraseña maestra.
 */
import { NextResponse } from "next/server";
import { randomBytes } from "node:crypto";

const GOOGLE_OIDC_URL = "https://accounts.google.com/o/oauth2/v2/auth";

export async function GET() {
  const clientId = process.env.OIDC_CLIENT_ID;
  if (!clientId) {
    return NextResponse.json(
      { error: "OIDC no configurado. Define OIDC_CLIENT_ID." },
      { status: 501 },
    );
  }

  const redirectUri = process.env.OIDC_REDIRECT_URI || "http://localhost:3000/api/auth/oidc/callback";

  // PKCE: generar code_verifier y code_challenge
  const codeVerifier = randomBytes(32).toString("base64url");
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(codeVerifier));
  const codeChallenge = Buffer.from(hash).toString("base64url");

  // Guardar code_verifier en cookie httpOnly
  const state = randomBytes(16).toString("hex");

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  });

  const response = NextResponse.redirect(`${GOOGLE_OIDC_URL}?${params.toString()}`);
  response.cookies.set("oidc_state", state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 600, // 10 min
  });
  response.cookies.set("oidc_verifier", codeVerifier, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 600,
  });

  return response;
}
