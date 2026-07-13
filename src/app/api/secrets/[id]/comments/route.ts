/**
 * /api/secrets/[id]/comments
 *   GET — Lista comentarios cifrados de un secreto.
 *   POST — Crea un comentario cifrado.
 *
 *
 * Los comentarios se cifran con la misma llave AES del secreto.
 * El servidor solo almacena blobs cifrados.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { pathIdSchema, validatePayload } from "@/lib/validation-schemas";
import {
  IV_EXPECTED_BYTES,
  MAX_BLOB_BYTES,
  validateBase64Blob,
} from "@/lib/crypto-server";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id } = await params;
  const idValidation = validatePayload(pathIdSchema, id);
  if (!idValidation.success) {
    return NextResponse.json({ error: idValidation.error }, { status: 400 });
  }
  const secretId = idValidation.data;

  // Verificar acceso
  const share = await db.secretKeyShare.findUnique({
    where: { secretId_recipientId: { secretId, recipientId: userId } },
  });
  if (!share) {
    return NextResponse.json({ error: "No tienes acceso a este secreto" }, { status: 403 });
  }

  const comments = await db.secretComment.findMany({
    where: { secretId },
    orderBy: { createdAt: "asc" },
    include: {
      author: { select: { email: true, name: true } },
    },
  });

  return NextResponse.json({
    comments: comments.map((c) => ({
      id: c.id,
      authorEmail: c.author.email,
      authorName: c.author.name,
      encryptedText: c.encryptedText,
      textIv: c.textIv,
      createdAt: c.createdAt,
    })),
  });
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id } = await params;
  const idValidation = validatePayload(pathIdSchema, id);
  if (!idValidation.success) {
    return NextResponse.json({ error: idValidation.error }, { status: 400 });
  }
  const secretId = idValidation.data;

  // Verificar acceso
  const share = await db.secretKeyShare.findUnique({
    where: { secretId_recipientId: { secretId, recipientId: userId } },
  });
  if (!share) {
    return NextResponse.json({ error: "No tienes acceso a este secreto" }, { status: 403 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { encryptedText, textIv } = body ?? {};

  if (!validateBase64Blob(encryptedText, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `encryptedText debe ser base64 ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(textIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `textIv debe ser base64 de ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }

  const comment = await db.secretComment.create({
    data: {
      secretId,
      authorId: userId,
      encryptedText,
      textIv,
    },
  });

  return NextResponse.json({
    commentId: comment.id,
    createdAt: comment.createdAt,
  });
}
