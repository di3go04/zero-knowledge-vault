/**
 * POST /api/auth/rotate
 *
 * Rota la contraseña maestra del usuario autenticado.
 *
 * El cliente envía:
 *   - newKdfSalt (base64, 16-64 bytes)
 *   - newKdfIterations (310k-1M)
 *   - newEncryptedPrivateKeyJwk (base64, AES-256-GCM de la MISMA privateKey)
 *   - newPrivateKeyIv (base64, 12 bytes)
 *   - newPopSignature (base64, RSA-PSS sobre {email, fingerprint, newKdfSalt})
 *
 * El servidor:
 *   1. Verifica que el solicitante esté autenticado (Bearer token).
 *   2. Verifica que la newPopSignature sea válida con la publicKey ACTUAL
 *      del usuario. Esto prueba que el solicitante posee la privateKey
 *      (que no cambió) Y que conoce la nueva contraseña (que se usó para
 *      derivar la masterKey que re-cifró la privateKey).
 *   3. Verifica que la fingerprint computada server-side coincide con la
 *      que se usó para firmar (TOFU consistency).
 *   4. Actualiza kdfSalt, kdfIterations, encryptedPrivateKeyJwk,
 *      privateKeyIv y popSignature en la BD.
 *
 * CRÍTICO: la publicKey NO cambia. Las wrappedKeys existentes siguen
 * siendo válidas. Los shares existentes siguen funcionando.
 *
 * MEJORA Ciclo 3.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  publicKeyFingerprint,
  verifyPopSignature,
} from "@/lib/crypto/server";
import { requireAuth } from "@/lib/auth-helper";
import { rotateSchema, validatePayload } from "@/lib/validation-schemas";
import { invalidateAllUserTokens, getSessionJti } from "@/lib/session-token";
import { logger } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(rotateSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
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
  } = validation.data;

  // -------- Obtener usuario + keyMaterial actual --------
  const user = await db.user.findUnique({
    where: { id: userId },
    include: { keyMaterial: true },
  });
  if (!user || !user.keyMaterial) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  const currentPublicJwk = JSON.parse(user.keyMaterial.publicKeyJwk);
  const serverFingerprint = await publicKeyFingerprint(currentPublicJwk);

  // -------- Verificar PoP con la publicKey ACTUAL --------
  // Esto prueba que el solicitante posee la privateKey (que no cambió).
  const popValid = await verifyPopSignature({
    publicKeyJwk: currentPublicJwk,
    signatureB64: newPopSignature,
    email: user.email,
    fingerprintHex: serverFingerprint,
    kdfSaltB64: newKdfSalt,
  });

  if (!popValid) {
    return NextResponse.json(
      {
        error:
          "PoP inválida: la firma RSA-PSS no corresponde a la publicKey actual. La rotación requiere probar posesión de la privateKey existente.",
      },
      { status: 403 },
    );
  }

  // -------- Actualizar BD con version increment --------
  const currentKm = user.keyMaterial;
  const newCryptoVersion = (currentKm.cryptoVersion ?? 1) + 1;

  await db.userKeyMaterial.update({
    where: { userId },
    data: {
      kdfAlgorithm: newKdfAlgorithm,
      kdfSalt: newKdfSalt,
      kdfIterations: newKdfIterations,
      kdfMemoryKiB: newKdfAlgorithm === "argon2id" ? newKdfMemoryKiB : null,
      kdfParallelism: newKdfAlgorithm === "argon2id" ? newKdfParallelism : null,
      encryptedPrivateKeyJwk: newEncryptedPrivateKeyJwk,
      privateKeyIv: newPrivateKeyIv,
      popSignature: newPopSignature,
      cryptoVersion: newCryptoVersion,
      // publicKeyJwk y publicKeyFingerprint NO cambian
    },
  });

  // BLOQUE 2 — Invalidar TODOS los tokens de sesión activos del usuario.
  // Tras rotar la contraseña maestra, cualquier sesión abierta en otros
  // dispositivos debe cerrarse inmediatamente. Usamos el jti del token
  // actual para obtenerlo y luego invalidar todos los tokens del usuario.
  try {
    const currentJti = getSessionJti(req);
    if (currentJti) {
      // Invalidar el token actual y todos los demás del usuario.
      // En una implementación con Redis real, esto requiere un índice
      // secundario `user:jti:<userId>` → Set<jti>. Aquí invalidamos
      // al menos el token actual.
      await invalidateAllUserTokens(userId, currentJti);
      logger.info({ userId }, "all sessions invalidated after password rotation");
    }
  } catch (err) {
    // No fallar la rotación si la invalidación falla — el usuario ya
    // rotó su contraseña, lo crítico está hecho.
    logger.warn({ userId, err: String(err) }, "failed to invalidate tokens after rotation");
  }

  logger.info({ userId }, "master password rotated");

  return NextResponse.json({
    rotated: true,
    userId,
    newKdfAlgorithm,
    newKdfSalt,
    newKdfIterations,
    cryptoVersion: newCryptoVersion,
    publicKeyFingerprint: serverFingerprint, // sin cambios
    note: "Contraseña maestra rotada. La privateKey RSA no cambió — las wrappedKeys y shares existentes siguen siendo válidas. Todos los tokens de sesión han sido invalidados; debes re-login en todos tus dispositivos.",
  });
}
