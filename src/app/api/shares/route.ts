/**
 * POST /api/shares
 *   Crea o actualiza un SecretKeyShare.
 *
 * DELETE /api/shares
 *   Revoca un share existente. Solo el owner del secreto puede revocar.
 *   Esto es el "offboarding" — si Bob deja el equipo, Alice revoca su
 *   acceso a todos los secretos que le compartió. Bob ya no podrá
 *   desenvolver la AES key del secreto (su wrappedKey se borra).
 *
 * Body POST: { secretId, recipientId, wrappedSymmetricKey (base64) }
 * Body DELETE: { secretId, recipientId }
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { createShareSchema, revokeShareSchema, validatePayload } from "@/lib/validation-schemas";
import { checkRateLimit, rateLimitResponse, getClientIp } from "@/lib/rate-limit";
import { logger } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const ownerId = auth.userId;

  // Rate limit: 30 share creations per 15 min per IP+user
  const ip = getClientIp(req);
  const rl = await checkRateLimit(`shares:create:${ip}:${ownerId}`, 30, 15 * 60 * 1000);
  if (!rl.allowed) {
    logger.warn({ ownerId, ip }, "rate limited on share creation");
    return rateLimitResponse(rl.retryAfterSeconds, rl.remaining);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(createShareSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { secretId, recipientId, wrappedSymmetricKey } = validation.data;

  try {
    const secret = await db.secret.findUnique({ where: { id: secretId } });
    if (!secret) {
      return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
    }
    if (secret.ownerId !== ownerId) {
      logger.warn({ ownerId, secretId, realOwner: secret.ownerId }, "non-owner attempted share");
      return NextResponse.json(
        { error: "Solo el owner puede compartir el secreto" },
        { status: 403 },
      );
    }

    if (recipientId === ownerId) {
      return NextResponse.json(
        { error: "No puedes compartir contigo mismo — ya tienes acceso" },
        { status: 400 },
      );
    }

    const recipient = await db.user.findUnique({
      where: { id: recipientId },
      include: { keyMaterial: true },
    });
    if (!recipient || !recipient.keyMaterial) {
      return NextResponse.json({ error: "Destinatario no encontrado" }, { status: 404 });
    }

    const share = await db.secretKeyShare.upsert({
      where: {
        secretId_recipientId: { secretId, recipientId },
      },
      update: { wrappedSymmetricKey },
      create: {
        secretId,
        recipientId,
        wrappedSymmetricKey,
      },
    });

    logger.info({ ownerId, secretId, recipientId, shareId: share.id }, "share created");
    return NextResponse.json({
      shareId: share.id,
      secretId,
      recipientId,
      recipientEmail: recipient.email,
      recipientFingerprint: recipient.keyMaterial.publicKeyFingerprint,
      createdAt: share.createdAt,
    });
  } catch (err) {
    logger.error({ err, ownerId, secretId, recipientId }, "failed to create share");
    return NextResponse.json({ error: "Error al crear share" }, { status: 500 });
  }
}

// ----------------------- DELETE (revoke share) -----------------------
/**
 * Dos modos de revocación:
 *
 * 1. OWNER revoca acceso a un destinatario:
 *    El solicitante es el owner del secreto, recipientId es otro usuario.
 *    Caso de uso: offboarding — Bob deja el equipo, Alice le revoca acceso.
 *
 * 2. DESTINATARIO se auto-saca del secreto:
 *    El solicitante es el propio recipientId. No es el owner.
 *    Caso de uso: Bob decide salir voluntariamente de un secreto compartido.
 *
 * El owner NO puede revocar su propio acceso (tendría que borrar el secreto).
 * El destinatario solo puede revocar SU share, no el de otros.
 */
export async function DELETE(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const requesterId = auth.userId;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(revokeShareSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { secretId, recipientId } = validation.data;

  try {
    const secret = await db.secret.findUnique({ where: { id: secretId } });
    if (!secret) {
      return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
    }

    const isOwner = secret.ownerId === requesterId;
    const isSelfLeave = recipientId === requesterId;

    if (!isOwner && !isSelfLeave) {
      logger.warn({ requesterId, secretId, recipientId }, "unauthorized revoke attempt");
      return NextResponse.json(
        { error: "Solo el owner puede revocar shares de otros usuarios." },
        { status: 403 },
      );
    }

    if (isOwner && isSelfLeave) {
      return NextResponse.json(
        { error: "No puedes revocar tu propio acceso al secreto. Borra el secreto completo si lo necesitas." },
        { status: 400 },
      );
    }

    const recipient = await db.user.findUnique({ where: { id: recipientId } });
    if (!recipient) {
      return NextResponse.json({ error: "Destinatario no encontrado" }, { status: 404 });
    }

    const deleted = await db.secretKeyShare.deleteMany({
      where: { secretId, recipientId },
    });

    if (deleted.count === 0) {
      return NextResponse.json(
        { error: "No existía un share para ese destinatario" },
        { status: 404 },
      );
    }

    logger.info({ requesterId, secretId, recipientId, mode: isOwner ? "owner-revoke" : "self-leave" }, "share revoked");
    return NextResponse.json({
      secretId,
      recipientId,
      revoked: true,
      mode: isOwner ? "owner-revoke" : "self-leave",
    });
  } catch (err) {
    logger.error({ err, requesterId, secretId, recipientId }, "failed to revoke share");
    return NextResponse.json({ error: "Error al revocar share" }, { status: 500 });
  }
}
