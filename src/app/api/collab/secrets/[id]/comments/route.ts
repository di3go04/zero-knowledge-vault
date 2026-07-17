import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { createCommentSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;

  const comments = await db.comment.findMany({
    where: { secretId: id },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ comments });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;

  const secret = await db.secret.findUnique({ where: { id } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });

  const hasAccess = await db.secretKeyShare.findFirst({
    where: { secretId: id, recipientId: auth.userId },
  });
  if (secret.ownerId !== auth.userId && !hasAccess) {
    return NextResponse.json({ error: "No tienes acceso a este secreto" }, { status: 403 });
  }

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(createCommentSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { content, contentIv, mentions, parentId } = validation.data;

  const comment = await db.comment.create({
    data: {
      secretId: id,
      authorId: auth.userId,
      content,
      contentIv: contentIv ?? null,
      mentions: mentions ? JSON.stringify(mentions) : null,
      parentId: parentId ?? null,
    },
  });

  if (mentions && mentions.length > 0) {
    const author = await db.user.findUnique({ where: { id: auth.userId }, select: { name: true, email: true } });
    for (const mentionedId of mentions) {
      await db.notification.create({
        data: {
          userId: mentionedId,
          type: "comment",
          title: `${author?.name ?? author?.email ?? "Alguien"} te mencionó en un comentario`,
          data: JSON.stringify({ secretId: id, commentId: comment.id }),
        },
      });
    }
  }

  return NextResponse.json(comment, { status: 201 });
}
