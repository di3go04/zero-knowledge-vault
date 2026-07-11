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
import { loginSchema, validatePayload } from "@/lib/validation-schemas";
import { checkRateLimit, resetRateLimit, getClientIp, RATE_LIMIT_POLICIES } from "@/lib/rate-limit";

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(loginSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const email = validation.data.email;
  const normalizedEmail = email.toLowerCase().trim();
  const ip = getClientIp(req);

  // -------- Rate limit (async — usa Redis o Map) --------
  const rlKey = `login:${ip}:${normalizedEmail}`;
  const rl = await checkRateLimit(
    rlKey,
    RATE_LIMIT_POLICIES.login.maxAttempts,
    RATE_LIMIT_POLICIES.login.windowMs,
  );
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
    await resetRateLimit(rlKey);

    const km = user.keyMaterial;
    const fingerprint = km.publicKeyFingerprint;
    const sessionToken = issueSessionToken(user.id);
    const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL;

    return NextResponse.json({
      userId: user.id,
      email: user.email,
      name: user.name,
      kdfAlgorithm: km.kdfAlgorithm, // "argon2id" | "pbkdf2"
      kdfSalt: km.kdfSalt,
      kdfIterations: km.kdfIterations,
      kdfMemoryKiB: km.kdfMemoryKiB, // null para PBKDF2
      kdfParallelism: km.kdfParallelism, // null para PBKDF2
      encryptedPrivateKeyJwk: km.encryptedPrivateKeyJwk,
      privateKeyIv: km.privateKeyIv,
      publicKeyJwk: JSON.parse(km.publicKeyJwk),
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
    kdfAlgorithm: "argon2id" as const, // mismo algoritmo que cuentas reales
    kdfSalt: decoy.kdfSalt,
    kdfIterations: decoy.kdfIterations,
    kdfMemoryKiB: 65536, // 64 MiB — plausible
    kdfParallelism: 4,
    encryptedPrivateKeyJwk: decoy.encryptedPrivateKeyJwk,
    privateKeyIv: decoy.privateKeyIv,
    publicKeyJwk: decoy.publicKeyJwk,
    publicKeyFingerprint: await publicKeyFingerprint(decoy.publicKeyJwk as Record<string, unknown>),
    sessionToken: null,
    expiresAt: null,
    isDecoy: true,
  });
}
