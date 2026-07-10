/**
 * POST /api/shares
 *
 * Crea un nuevo SecretKeyShare: almacena la llave AES del secreto
 * ENVUELTA (wrapped) con la llave PÚBLICA RSA del destinatario.
 *
 * El servidor NO puede desenvolverla (no tiene la llave privada del
 * destinatario). Por tanto, aun en caso de brecha, el atacante no
 * obtiene la llave simétrica en claro.
 *
 * Header: x-user-id (debe ser el owner del secreto)
 *
 * Body:
 *   { secretId, recipientId, wrappedSymmetricKey (base64) }
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

const isBase64 = (s: unknown): s is string =>
  typeof s === "string" && s.length > 0 && /^[A-Za-z0-9+/=_-]+$/.test(s);

export async function POST(req: NextRequest) {
  const ownerId = req.headers.get("x-user-id");
  if (!ownerId) {
    return NextResponse.json({ error: "No autenticado" }, { status: 401 });
  }

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
  if (!isBase64(wrappedSymmetricKey)) {
    return NextResponse.json(
      { error: "wrappedSymmetricKey debe ser base64 (RSA-OAEP wrapped AES key)" },
      { status: 400 },
    );
  }

  // Verificar que el solicitante es el owner del secreto
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

  // No compartir consigo mismo
  if (recipientId === ownerId) {
    return NextResponse.json(
      { error: "No puedes compartir contigo mismo — ya tienes acceso" },
      { status: 400 },
    );
  }

  // Verificar que el destinatario exista
  const recipient = await db.user.findUnique({ where: { id: recipientId } });
  if (!recipient) {
    return NextResponse.json({ error: "Destinatario no encontrado" }, { status: 404 });
  }

  // Idempotente: si ya existe, reemplazamos la wrappedKey (rotación de acceso)
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
    createdAt: share.createdAt,
  });
}
