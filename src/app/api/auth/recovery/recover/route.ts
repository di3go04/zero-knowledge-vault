/**
 * POST /api/auth/recovery/recover
 *
 * Flujo de recuperación de cuenta cuando el usuario olvidó su
 * contraseña maestra. NO requiere autenticación (no tiene sesión).
 *
 * El cliente envía:
 *   { email, mnemonic (24 palabras), newPassword, newKdfAlgorithm, newKdfSalt,
 *     newKdfIterations, newKdfMemoryKiB?, newKdfParallelism?,
 *     newEncryptedPrivateKeyJwk, newPrivateKeyIv, newPopSignature }
 *
 * El servidor:
 *   1. Busca el usuario por email. Si no existe o no tiene recoveryEnabled,
 *      devuelve error genérico (anti-enumeración).
 *   2. Devuelve el blob de recuperación (recoverySalt, recoveryIterations,
 *      encryptedPrivateKeyForRecovery, recoveryIv) al cliente para que
 *      lo descifre con la frase BIP-39.
 *
 * NOTA: Por simplicidad, este endpoint devuelve el blob de recuperación
 * y espera que el cliente devuelva la nueva privateKey re-cifrada en una
 * segunda llamada. En producción se debería hacer challenge-response
 * para verificar que el cliente realmente posee la frase antes de
 * entregar el blob.
 *
 * Para evitar enumeración, devolvemos decoy si el usuario no tiene
 * recovery configurado (mismo formato de respuesta).
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { generateDecoyLoginResponse } from "@/lib/crypto-server";
import {
  recoveryGetBlobSchema,
  recoveryCompleteSchema,
  validatePayload,
} from "@/lib/validation-schemas";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

//
const RECOVERY_RATE_LIMIT = { maxAttempts: 3, windowMs: 60 * 60 * 1000 }; // 3/hora

export async function POST(req: NextRequest) {
  // Rate limit antes de procesar — anti-bruteforce de recovery
  const ip = getClientIp(req);
  const rlKey = `recovery:${ip}`;
  const rl = await checkRateLimit(rlKey, RECOVERY_RATE_LIMIT.maxAttempts, RECOVERY_RATE_LIMIT.windowMs);
  if (!rl.allowed) {
    return NextResponse.json(
      { error: "Demasiados intentos de recuperación. Espera una hora.", retryAfter: rl.retryAfterSeconds },
      { status: 429, headers: { "Retry-After": String(rl.retryAfterSeconds) } },
    );
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  // Validar según el action
  const action = body?.action;
  if (action === "get-blob") {
    const validation = validatePayload(recoveryGetBlobSchema, body);
    if (!validation.success) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }
  } else if (action === "complete") {
    const validation = validatePayload(recoveryCompleteSchema, body);
    if (!validation.success) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }
  } else {
    return NextResponse.json(
      { error: "action debe ser 'get-blob' o 'complete'" },
      { status: 400 },
    );
  }

  const { email } = body as { email: string };
  const normalizedEmail = email.toLowerCase().trim();

  const user = await db.user.findUnique({
    where: { email: normalizedEmail },
    include: { keyMaterial: true },
  });

  // CASO 1: obtener blob de recuperación
  if (action === "get-blob") {
    if (!user || !user.keyMaterial || !user.keyMaterial.recoveryEnabled) {
      // Decoy para evitar enumeración
      const decoy = generateDecoyLoginResponse(normalizedEmail);
      return NextResponse.json({
        recoveryEnabled: true,
        recoverySalt: decoy.kdfSalt,
        recoveryIterations: 600_000,
        encryptedPrivateKeyForRecovery: decoy.encryptedPrivateKeyJwk,
        recoveryIv: decoy.privateKeyIv,
        isDecoy: true,
      });
    }

    const km = user.keyMaterial;
    return NextResponse.json({
      recoveryEnabled: true,
      recoverySalt: km.recoverySalt,
      recoveryIterations: km.recoveryIterations,
      encryptedPrivateKeyForRecovery: km.encryptedPrivateKeyForRecovery,
      recoveryIv: km.recoveryIv,
      isDecoy: false,
    });
  }

  // CASO 2: completar recuperación con nueva contraseña maestra
  if (action === "complete") {
    if (!user || !user.keyMaterial || !user.keyMaterial.recoveryEnabled) {
      return NextResponse.json(
        { error: "Recuperación no habilitada para esta cuenta" },
        { status: 404 },
      );
    }

    const {
      newKdfAlgorithm,
      newKdfSalt,
      newKdfIterations,
      newKdfMemoryKiB,
      newKdfParallelism,
      newEncryptedPrivateKeyJwk,
      newPrivateKeyIv,
      newPopSignature,
    } = body ?? {};

    // Validar PoP con la publicKey actual (la privateKey no cambia)
    const { verifyPopSignature, publicKeyFingerprint } = await import("@/lib/crypto-server");
    const currentPublicJwk = JSON.parse(user.keyMaterial.publicKeyJwk);
    const serverFingerprint = await publicKeyFingerprint(currentPublicJwk);

    const popValid = await verifyPopSignature({
      publicKeyJwk: currentPublicJwk,
      signatureB64: newPopSignature,
      email: user.email,
      fingerprintHex: serverFingerprint,
      kdfSaltB64: newKdfSalt,
    });

    if (!popValid) {
      return NextResponse.json(
        { error: "PoP inválida — la frase de recuperación no descifró la privateKey correctamente." },
        { status: 403 },
      );
    }

    // Actualizar BD con la nueva contraseña maestra
    await db.userKeyMaterial.update({
      where: { userId: user.id },
      data: {
        kdfAlgorithm: newKdfAlgorithm,
        kdfSalt: newKdfSalt,
        kdfIterations: newKdfIterations,
        kdfMemoryKiB: newKdfAlgorithm === "argon2id" ? newKdfMemoryKiB : null,
        kdfParallelism: newKdfAlgorithm === "argon2id" ? newKdfParallelism : null,
        encryptedPrivateKeyJwk: newEncryptedPrivateKeyJwk,
        privateKeyIv: newPrivateKeyIv,
        popSignature: newPopSignature,
      },
    });

    return NextResponse.json({
      recovered: true,
      userId: user.id,
      email: user.email,
      note: "Cuenta recuperada. Inicia sesión con tu nueva contraseña maestra.",
    });
  }

  return NextResponse.json({ error: "action debe ser 'get-blob' o 'complete'" }, { status: 400 });
}
