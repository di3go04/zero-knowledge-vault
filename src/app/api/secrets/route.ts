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

const isBase64 = (s: unknown): s is string =>
  typeof s === "string" && s.length > 0 && /^[A-Za-z0-9+/=_-]+$/.test(s);

function getUserId(req: NextRequest): string | null {
  const id = req.headers.get("x-user-id");
  return id && id.length > 0 ? id : null;
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

  // Validación estricta: TODO debe ser blob cifrado. Nada en claro.
  const fields = { encryptedTitle, titleIv, encryptedData, dataIv, wrappedKeyForOwner };
  for (const [k, v] of Object.entries(fields)) {
    if (!isBase64(v)) {
      return NextResponse.json(
        { error: `Campo '${k}' debe ser base64 (blob cifrado). El servidor rechaza cualquier valor en claro.` },
        { status: 400 },
      );
    }
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
