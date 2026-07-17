/**
 * /api/secrets
 *   GET  — Lista secretos propios + compartidos con el usuario autenticado.
 *   POST — Crea un nuevo secreto. Recibe solo blobs cifrados.
 *
 * El servidor nunca ve la llave maestra, la llave privada RSA, ni el
 * contenido plano del secreto — solo blobs AES-GCM ciphertext + la llave
 * AES envuelta (RSA-OAEP) para cada destinatario.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { createSecretSchema, validatePayload } from "@/lib/validation-schemas";
import { checkRateLimit, rateLimitResponse, getClientIp } from "@/lib/rate-limit";
import { logger } from "@/lib/logger";

// ----------------------- GET (list) -----------------------
export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const url = req.nextUrl;
  const cursor = url.searchParams.get("cursor");
  const limit = Math.min(parseInt(url.searchParams.get("limit") ?? "50", 10), 100);

  try {
    const shares = await db.secretKeyShare.findMany({
      where: {
        recipientId: userId,
        ...(cursor ? { createdAt: { lt: new Date(cursor) } } : {}),
      },
      include: {
        secret: {
          include: {
            owner: { select: { id: true, email: true, name: true } },
          },
        },
      },
      orderBy: { createdAt: "desc" },
      take: limit + 1,
    });

    const hasMore = shares.length > limit;
    const items = hasMore ? shares.slice(0, limit) : shares;
    const nextCursor = hasMore ? items[items.length - 1].createdAt.toISOString() : null;

    const result = items.map((s) => ({
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

    logger.debug({ userId, count: result.length }, "listed secrets");
    return NextResponse.json({ secrets: result, nextCursor, hasMore });
  } catch (err) {
    logger.error({ err, userId }, "failed to list secrets");
    return NextResponse.json({ error: "Error al listar secretos" }, { status: 500 });
  }
}

// ----------------------- POST (create) -----------------------
export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  // Rate limit: 30 secret creations per 15 min per IP+user
  const ip = getClientIp(req);
  const rl = await checkRateLimit(`secrets:create:${ip}:${userId}`, 30, 15 * 60 * 1000);
  if (!rl.allowed) {
    logger.warn({ userId, ip }, "rate limited on secret creation");
    return rateLimitResponse(rl.retryAfterSeconds, rl.remaining);
  }

  let body: unknown;
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

  try {
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

    logger.info({ userId, secretId: secret.id }, "secret created");
    return NextResponse.json({ secretId: secret.id, createdAt: secret.createdAt });
  } catch (err) {
    logger.error({ err, userId }, "failed to create secret");
    return NextResponse.json({ error: "Error al crear secreto" }, { status: 500 });
  }
}
