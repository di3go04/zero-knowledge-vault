/**
 * POST /api/auth/login
 *
 * MEJORAS Ciclo 2:
 *   1. Rate-limiting: 5 intentos / 15 min / IP+email. Devuelve 429 con
 *      Retry-After si se excede. Previene ataques de fuerza bruta que
 *      intentan obtener material para brute-force offline.
 *   2. Emite un session token HMAC-signed (HS256) que el cliente debe
 *      enviar en `Authorization: Bearer <token>` en todas las requests
 *      autenticadas. Reemplaza el header x-user-id que era forjable.
 *
 * Body: { email }
 * Response (real o decoy):
 *   { userId, email, name, kdfSalt, kdfIterations,
 *     encryptedPrivateKeyJwk, privateKeyIv, publicKeyJwk,
 *     publicKeyFingerprint, sessionToken, expiresAt, isDecoy? }
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  generateDecoyLoginResponse,
  publicKeyFingerprint,
} from "@/lib/crypto-server";
import { issueSessionToken, SESSION_TTL } from "@/lib/session-token";
import { checkRateLimit, resetRateLimit } from "@/lib/rate-limit";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function getClientIp(req: NextRequest): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  const xri = req.headers.get("x-real-ip");
  if (xri) return xri;
  return "unknown";
}

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const email = body?.email;
  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "email inválido" }, { status: 400 });
  }
  const normalizedEmail = email.toLowerCase().trim();
  const ip = getClientIp(req);

  // -------- Rate limit --------
  // Clave compuesta: IP + email. Así, un atacante desde una IP no puede
  // atacar a múltiples emails sin que se le agote el cupo por IP.
  const rlKey = `login:${ip}:${normalizedEmail}`;
  const rl = checkRateLimit(rlKey, 5, 15 * 60 * 1000);
  if (!rl.allowed) {
    return NextResponse.json(
      {
        error: "Demasiados intentos. Intenta más tarde.",
        retryAfter: rl.retryAfterSeconds,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(rl.retryAfterSeconds),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(rl.retryAfterSeconds),
        },
      },
    );
  }

  const user = await db.user.findUnique({
    where: { email: normalizedEmail },
    include: { keyMaterial: true },
  });

  // -------- CASO 1: usuario real --------
  if (user && user.keyMaterial) {
    // Resetear rate-limit tras login exitoso (el usuario legitimo no debe
    // ser penalizado por intentos previos fallidos suyos).
    resetRateLimit(rlKey);

    const fingerprint = user.keyMaterial.publicKeyFingerprint;
    const sessionToken = issueSessionToken(user.id);
    const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL;

    return NextResponse.json({
      userId: user.id,
      email: user.email,
      name: user.name,
      kdfSalt: user.keyMaterial.kdfSalt,
      kdfIterations: user.keyMaterial.kdfIterations,
      encryptedPrivateKeyJwk: user.keyMaterial.encryptedPrivateKeyJwk,
      privateKeyIv: user.keyMaterial.privateKeyIv,
      publicKeyJwk: JSON.parse(user.keyMaterial.publicKeyJwk),
      publicKeyFingerprint: fingerprint,
      sessionToken,
      expiresAt,
      isDecoy: false,
    });
  }

  // -------- CASO 2: usuario inexistente → DECOY --------
  // IMPORTANTE: NO reseteamos el rate-limit aquí, para que un atacante
  // que sonda emails inexistentes consuma su cupo de intentos.
  const decoy = generateDecoyLoginResponse(normalizedEmail);
  return NextResponse.json({
    userId: `decoy-${normalizedEmail}`,
    email: normalizedEmail,
    name: null,
    kdfSalt: decoy.kdfSalt,
    kdfIterations: decoy.kdfIterations,
    encryptedPrivateKeyJwk: decoy.encryptedPrivateKeyJwk,
    privateKeyIv: decoy.privateKeyIv,
    publicKeyJwk: decoy.publicKeyJwk,
    publicKeyFingerprint: await publicKeyFingerprint(decoy.publicKeyJwk as Record<string, unknown>),
    sessionToken: null, // no se emite token para decoys
    expiresAt: null,
    isDecoy: true,
  });
}
