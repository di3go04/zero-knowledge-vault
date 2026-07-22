/**
 * POST /api/auth/register
 *
 * Recibe EXCLUSIVAMENTE blobs cifrados y llaves públicas.
 * Validaciones server-side (Ciclo 1 de auditoría):
 *   - kdfIterations ∈ [310_000, 1_000_000] (anti-DoS + mínimo OWASP)
 *   - kdfSalt decodificado ∈ [16, 64] bytes
 *   - privateKeyIv decodificado = 12 bytes exactos
 *   - encryptedPrivateKeyJwk ≤ 64 KiB
 *   - publicKeyJwk ≤ 4 KiB y contiene kty, n, e
 *   - popSignature ≤ 512 bytes y es RSA-PSS válida sobre
 *     {email, publicKeyFingerprint, kdfSalt}
 *
 * El servidor NO descifra nada. Solo verifica la firma PoP con la
 * publicKey que el cliente declara — esto prueba que el cliente posee
 * la privateKey correspondiente, previniendo sustitución de publicKey.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { logger } from "@/lib/logger";
import {
  publicKeyFingerprint,
  verifyPopSignature,
} from "@/lib/crypto/server";
import { registerSchema, validatePayload } from "@/lib/validation-schemas";
import { checkRateLimit, getClientIp, rateLimitResponse } from "@/lib/rate-limit";

const NAME_MAX_LEN = 100;

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const ipRl = await checkRateLimit(`register:ip:${ip}`, 10, 60 * 60 * 1000);
  if (!ipRl.allowed) {
    logger.warn({ ip }, "register rate limited");
    return rateLimitResponse(ipRl.retryAfterSeconds, ipRl.remaining);
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  // Validación con Zod — rechaza cualquier campo que no sea un blob
  // cifrado válido o un parámetro en rango.
  const validation = validatePayload(registerSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const {
    email,
    name,
    kdfAlgorithm,
    kdfSalt,
    kdfIterations,
    kdfMemoryKiB,
    kdfParallelism,
    publicKeyJwk,
    encryptedPrivateKeyJwk,
    privateKeyIv,
    popSignature,
    mlKemPublicKey,
    encryptedMlKemPrivateKey,
    mlKemPrivateKeyIv,
  } = validation.data;

  const normalizedEmail = email.toLowerCase().trim();
  const jwkStr = JSON.stringify(publicKeyJwk);

  // -------- Verificar PoP ANTES de tocar la BD --------
  const serverFingerprint = await publicKeyFingerprint(publicKeyJwk as Record<string, unknown>);

  const popValid = await verifyPopSignature({
    publicKeyJwk: publicKeyJwk as JsonWebKey,
    signatureB64: popSignature,
    email: normalizedEmail,
    fingerprintHex: serverFingerprint,
    kdfSaltB64: kdfSalt,
  });

  if (!popValid) {
    return NextResponse.json(
      {
        error:
          "Proof-of-Possession inválida: la firma RSA-PSS no corresponde a la publicKey declarada. Posible intento de sustitución de llave.",
      },
      { status: 403 },
    );
  }

  // -------- Verificar unicidad --------
  const existing = await db.user.findUnique({ where: { email: normalizedEmail } });
  if (existing) {
    return NextResponse.json({ error: "El email ya está registrado" }, { status: 409 });
  }

  // -------- Persistir --------
  const user = await db.user.create({
    data: {
      email: normalizedEmail,
      name:
        typeof name === "string" && name.trim() ? name.trim().slice(0, NAME_MAX_LEN) : null,
      keyMaterial: {
        create: {
          kdfAlgorithm,
          kdfSalt,
          kdfIterations,
          kdfMemoryKiB: kdfAlgorithm === "argon2id" ? kdfMemoryKiB : null,
          kdfParallelism: kdfAlgorithm === "argon2id" ? kdfParallelism : null,
          publicKeyJwk: jwkStr,
          publicKeyFingerprint: serverFingerprint,
          popSignature,
          popSignatureHash: "SHA-256",
          encryptedPrivateKeyJwk,
          privateKeyIv,
          mlKemPublicKey: mlKemPublicKey ?? null,
          encryptedMlKemPrivateKey: encryptedMlKemPrivateKey ?? null,
          mlKemPrivateKeyIv: mlKemPrivateKeyIv ?? null,
        },
      },
    },
    include: { keyMaterial: true },
  });

  logger.info({ userId: user.id, email: user.email, kdfAlgorithm }, "user registered");
  return NextResponse.json({
    userId: user.id,
    email: user.email,
    name: user.name,
    publicKeyFingerprint: serverFingerprint,
    createdAt: user.createdAt,
  });
}
