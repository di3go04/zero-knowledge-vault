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
 * MEJORA Ciclo 2: usa Authorization: Bearer + añade endpoint DELETE.
 *
 * Body POST: { secretId, recipientId, wrappedSymmetricKey (base64) }
 * Body DELETE: { secretId, recipientId }
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { validateBase64Blob } from "@/lib/crypto-server";
import { requireAuth } from "@/lib/auth-helper";

const WRAPPED_KEY_BYTES = 256;

export async function POST(req: NextRequest) {
  const auth = requireAuth(req);
  if (!auth.ok) return auth.response;
  const ownerId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { secretId, recipientId, wrappedSymmetricKey } = body ?? {};

  if (typeof secretId !== "string" || !secretId) {
    return NextResponse.json({ error: "secretId requerido" }, { status: 400 });
  }
  if (typeof recipientId !== "string" || !recipientId) {
    return NextResponse.json({ error: "recipientId requerido" }, { status: 400 });
  }
  if (
    !validateBase64Blob(wrappedSymmetricKey, WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES)
  ) {
    return NextResponse.json(
      {
        error: `wrappedSymmetricKey debe ser base64 de exactamente ${WRAPPED_KEY_BYTES} bytes (RSA-OAEP-2048 wrapped AES key)`,
      },
      { status: 400 },
    );
  }

  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) {
    return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  }
  if (secret.ownerId !== ownerId) {
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

  return NextResponse.json({
    shareId: share.id,
    secretId,
    recipientId,
    recipientEmail: recipient.email,
    recipientFingerprint: recipient.keyMaterial.publicKeyFingerprint,
    createdAt: share.createdAt,
  });
}

// ----------------------- DELETE (revoke share) -----------------------
export async function DELETE(req: NextRequest) {
  const auth = requireAuth(req);
  if (!auth.ok) return auth.response;
  const ownerId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { secretId, recipientId } = body ?? {};
  if (typeof secretId !== "string" || !secretId) {
    return NextResponse.json({ error: "secretId requerido" }, { status: 400 });
  }
  if (typeof recipientId !== "string" || !recipientId) {
    return NextResponse.json({ error: "recipientId requerido" }, { status: 400 });
  }

  // Verificar ownership
  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) {
    return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  }
  if (secret.ownerId !== ownerId) {
    return NextResponse.json(
      { error: "Solo el owner puede revocar shares" },
      { status: 403 },
    );
  }

  // No permitir revocar el share del propio owner (sería perder acceso)
  if (recipientId === ownerId) {
    return NextResponse.json(
      { error: "No puedes revocar tu propio acceso al secreto" },
      { status: 400 },
    );
  }

  // Borrar el share
  const deleted = await db.secretKeyShare.deleteMany({
    where: { secretId, recipientId },
  });

  if (deleted.count === 0) {
    return NextResponse.json(
      { error: "No existía un share para ese destinatario" },
      { status: 404 },
    );
  }

  return NextResponse.json({
    secretId,
    recipientId,
    revoked: true,
    note: "El destinatario ya no puede descifrar NUEVAS peticiones del secreto. Copias descifradas localmente NO pueden ser revocadas.",
  });
}
