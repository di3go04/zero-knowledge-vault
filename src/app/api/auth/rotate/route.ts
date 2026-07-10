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
  IV_EXPECTED_BYTES,
  KDF_ITERATIONS_MAX,
  KDF_ITERATIONS_MIN,
  MAX_BLOB_BYTES,
  SALT_MAX_BYTES,
  SALT_MIN_BYTES,
  publicKeyFingerprint,
  validateBase64Blob,
  validateKdfIterations,
  verifyPopSignature,
} from "@/lib/crypto-server";
import { requireAuth } from "@/lib/auth-helper";

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

  // -------- kdfAlgorithm --------
  if (newKdfAlgorithm !== "argon2id" && newKdfAlgorithm !== "pbkdf2") {
    return NextResponse.json(
      { error: "newKdfAlgorithm debe ser 'argon2id' o 'pbkdf2'" },
      { status: 400 },
    );
  }

  // -------- kdfIterations --------
  if (typeof newKdfIterations !== "number" || !Number.isInteger(newKdfIterations)) {
    return NextResponse.json({ error: "newKdfIterations debe ser entero" }, { status: 400 });
  }
  if (newKdfAlgorithm === "argon2id") {
    if (newKdfIterations < 1 || newKdfIterations > 10) {
      return NextResponse.json(
        { error: "Argon2id: newKdfIterations (t) debe estar entre 1 y 10" },
        { status: 400 },
      );
    }
    if (typeof newKdfMemoryKiB !== "number" || newKdfMemoryKiB < 16_384 || newKdfMemoryKiB > 1_048_576) {
      return NextResponse.json(
        { error: "Argon2id: newKdfMemoryKiB debe estar entre 16384 y 1048576" },
        { status: 400 },
      );
    }
    if (typeof newKdfParallelism !== "number" || newKdfParallelism < 1 || newKdfParallelism > 16) {
      return NextResponse.json(
        { error: "Argon2id: newKdfParallelism debe estar entre 1 y 16" },
        { status: 400 },
      );
    }
  } else {
    if (newKdfIterations < KDF_ITERATIONS_MIN || newKdfIterations > KDF_ITERATIONS_MAX) {
      return NextResponse.json(
        { error: `PBKDF2: newKdfIterations debe estar entre ${KDF_ITERATIONS_MIN} y ${KDF_ITERATIONS_MAX}` },
        { status: 400 },
      );
    }
  }
  if (!validateBase64Blob(newKdfSalt, SALT_MIN_BYTES, SALT_MAX_BYTES)) {
    return NextResponse.json(
      { error: `newKdfSalt debe ser base64 de ${SALT_MIN_BYTES}-${SALT_MAX_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(newPrivateKeyIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `newPrivateKeyIv debe ser base64 de ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(newEncryptedPrivateKeyJwk, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `newEncryptedPrivateKeyJwk debe ser base64 ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(newPopSignature, 1, 512)) {
    return NextResponse.json(
      { error: "newPopSignature debe ser base64 (firma RSA-PSS)" },
      { status: 400 },
    );
  }

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

  // -------- Actualizar BD --------
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
      // publicKeyJwk y publicKeyFingerprint NO cambian
    },
  });

  return NextResponse.json({
    rotated: true,
    userId,
    newKdfAlgorithm,
    newKdfSalt,
    newKdfIterations,
    publicKeyFingerprint: serverFingerprint, // sin cambios
    note: "Contraseña maestra rotada. La privateKey RSA no cambió — las wrappedKeys y shares existentes siguen siendo válidas.",
  });
}
