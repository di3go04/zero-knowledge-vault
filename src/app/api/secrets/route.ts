/**
 * /api/secrets
 *   GET  — Lista secretos propios + compartidos con el usuario autenticado.
 *   POST — Crea un nuevo secreto. Recibe solo blobs cifrados.
 *
 * MEJORA Ciclo 2: usa Authorization: Bearer <token> en lugar del
 * header x-user-id que era forjable.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { createSecretSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";

// ----------------------- GET (list) -----------------------
export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const [shares, total] = await Promise.all([
    db.secretKeyShare.findMany({
      where: { recipientId: userId },
      include: {
        secret: {
          include: {
            owner: { select: { id: true, email: true, name: true } },
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.secretKeyShare.count({
      where: { recipientId: userId },
    }),
  ]);

  const secrets = shares.map((s) => ({
    id: s.secret.id,
    ownerId: s.secret.ownerId,
    ownerEmail: s.secret.owner.email,
    ownerName: s.secret.owner.name,
    ownedByMe: s.secret.ownerId === userId,
    encryptedTitle: s.secret.encryptedTitle,
    titleIv: s.secret.titleIv,
    encryptedData: s.secret.encryptedData,
    dataIv: s.secret.dataIv,
    wrappedKey: s.wrappedSymmetricKey,
    createdAt: s.secret.createdAt,
    sharedAt: s.createdAt,
  }));

  return NextResponse.json({
    secrets,
    pagination: {
      offset,
      limit,
      total,
      hasMore: offset + limit < total,
    },
  });
}

// ----------------------- POST (create) -----------------------
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

  const validation = validatePayload(createSecretSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { encryptedTitle, titleIv, encryptedData, dataIv, wrappedKeyForOwner } = validation.data;

  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

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
