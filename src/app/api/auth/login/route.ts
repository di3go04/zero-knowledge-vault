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
} from "@/lib/crypto/server";
import { issueSessionToken, SESSION_TTL } from "@/lib/session-token";
import { loginSchema, validatePayload } from "@/lib/validation-schemas";
import { logger } from "@/lib/logger";
import { checkRateLimit, resetRateLimit, getClientIp, RATE_LIMIT_POLICIES, rateLimitResponse } from "@/lib/rate-limit";

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

  // -------- BLOQUE 2: Rate limit dual — por IP Y por email --------
  // Anti-bruteforce: bloqueamos tanto por IP (atacante distribuido)
  // como por email (cred stuffing desde múltiples IPs).
  const ipKey = `login:ip:${ip}`;
  const emailKey = `login:email:${normalizedEmail}`;

  const [ipRl, emailRl] = await Promise.all([
    checkRateLimit(ipKey, 20, 15 * 60 * 1000), // 20 intentos / 15 min / IP (cualquier email)
    checkRateLimit(emailKey, RATE_LIMIT_POLICIES.login.maxAttempts, RATE_LIMIT_POLICIES.login.windowMs), // 5 / 15 min / email
  ]);

  const rl = ipRl.allowed ? emailRl : ipRl;
  if (!rl.allowed) {
    logger.warn(
      { ip, email: normalizedEmail, reason: !ipRl.allowed ? "ip" : "email" },
      "login rate limited",
    );
    return rateLimitResponse(rl.retryAfterSeconds, rl.remaining);
  }
  // Mantener compatibilidad con el código existente que usa rlKey
  const rlKey = emailKey;
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

    logger.info({ userId: user.id, email: user.email }, "user logged in");
    return NextResponse.json({
      userId: user.id,
      email: user.email,
      name: user.name,
      kdfAlgorithm: km.kdfAlgorithm,
      kdfSalt: km.kdfSalt,
      kdfIterations: km.kdfIterations,
      kdfMemoryKiB: km.kdfMemoryKiB,
      kdfParallelism: km.kdfParallelism,
      encryptedPrivateKeyJwk: km.encryptedPrivateKeyJwk,
      privateKeyIv: km.privateKeyIv,
      encryptedMlKemPrivateKey: km.encryptedMlKemPrivateKey,
      mlKemPrivateKeyIv: km.mlKemPrivateKeyIv,
      mlKemPublicKey: km.mlKemPublicKey,
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
