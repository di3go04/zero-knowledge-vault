/**
 * /api/secrets
 *   GET  — Lista secretos propios + compartidos con el usuario autenticado.
 *           Devuelve metadata + el wrappedKey correspondiente al solicitante.
 *   POST — Crea un nuevo secreto. Recibe solo blobs cifrados.
 *
 * Header: x-user-id (identificador del usuario; en un sistema real sería un JWT).
 *
 * GET Response: [
 *   { id, ownerId, ownerEmail, ownerName, ownedByMe,
 *     encryptedTitle, titleIv, encryptedData, dataIv,
 *     wrappedKey (base64) — elAES key wrapped con MI llave pública,
 *     createdAt }
 * ]
 *
 * POST Body:
 *   { encryptedTitle, titleIv, encryptedData, dataIv, wrappedKeyForOwner }
 *   - Todos los campos son blobs base64. El servidor no puede leer ninguno.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  IV_EXPECTED_BYTES,
  MAX_BLOB_BYTES,
  validateBase64Blob,
} from "@/lib/crypto-server";

// Un wrappedKey RSA-OAEP-2048 son exactamente 256 bytes
const WRAPPED_KEY_BYTES = 256;

function getUserId(req: NextRequest): string | null {
  const id = req.headers.get("x-user-id");
  return id && id.length > 0 && !id.startsWith("decoy-") ? id : null;
}

// ----------------------- GET (list) -----------------------
export async function GET(req: NextRequest) {
  const userId = getUserId(req);
  if (!userId) {
    return NextResponse.json({ error: "No autenticado" }, { status: 401 });
  }

  // Buscar todos los SecretKeyShares del usuario; cada uno referencia un
  // secreto al que el usuario tiene acceso (propio o compartido).
  const shares = await db.secretKeyShare.findMany({
    where: { recipientId: userId },
    include: {
      secret: {
        include: {
          owner: { select: { id: true, email: true, name: true } },
        },
      },
    },
    orderBy: { createdAt: "desc" },
  });

  const result = shares.map((s) => ({
    id: s.secret.id,
    ownerId: s.secret.ownerId,
    ownerEmail: s.secret.owner.email,
    ownerName: s.secret.owner.name,
    ownedByMe: s.secret.ownerId === userId,
    encryptedTitle: s.secret.encryptedTitle,
    titleIv: s.secret.titleIv,
    encryptedData: s.secret.encryptedData,
    dataIv: s.secret.dataIv,
    wrappedKey: s.wrappedSymmetricKey, // SOLO la copia del solicitante
    createdAt: s.secret.createdAt,
    sharedAt: s.createdAt,
  }));

  return NextResponse.json({ secrets: result });
}

// ----------------------- POST (create) -----------------------
export async function POST(req: NextRequest) {
  const userId = getUserId(req);
  if (!userId) {
    return NextResponse.json({ error: "No autenticado" }, { status: 401 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { encryptedTitle, titleIv, encryptedData, dataIv, wrappedKeyForOwner } = body ?? {};

  // -------- Validación estricta: TODO debe ser blob cifrado + tamaños --------
  // IVs: exactamente 12 bytes (GCM recomendado)
  if (!validateBase64Blob(titleIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `titleIv debe ser base64 de exactamente ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(dataIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `dataIv debe ser base64 de exactamente ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }
  // Ciphertexts: 1 byte mínimo (no vacío), 64 KiB máximo (anti-DoS)
  if (!validateBase64Blob(encryptedTitle, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `encryptedTitle debe ser base64 (blob cifrado) ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(encryptedData, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `encryptedData debe ser base64 (blob cifrado) ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  // wrappedKey: RSA-OAEP-2048 → exactamente 256 bytes
  if (!validateBase64Blob(wrappedKeyForOwner, WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES)) {
    return NextResponse.json(
      { error: `wrappedKeyForOwner debe ser base64 de exactamente ${WRAPPED_KEY_BYTES} bytes (RSA-OAEP-2048)` },
      { status: 400 },
    );
  }

  // Verificar que el usuario exista (defense in depth)
  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  // Transacción: crear secreto + el primer SecretKeyShare para el owner
  const secret = await db.$transaction(async (tx) => {
    const newSecret = await tx.secret.create({
      data: {
        ownerId: userId,
        encryptedTitle,
        titleIv,
        encryptedData,
        dataIv,
      },
    });
    await tx.secretKeyShare.create({
      data: {
        secretId: newSecret.id,
        recipientId: userId,
        wrappedSymmetricKey: wrappedKeyForOwner,
      },
    });
    return newSecret;
  });

  return NextResponse.json({ secretId: secret.id, createdAt: secret.createdAt });
}
