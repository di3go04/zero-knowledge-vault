import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { updateCommentSchema, validatePayload } from "@/lib/validation-schemas";

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string; commentId: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { commentId } = await params;

  const comment = await db.comment.findUnique({ where: { id: commentId } });
  if (!comment) return NextResponse.json({ error: "Comentario no encontrado" }, { status: 404 });
  if (comment.authorId !== auth.userId) return NextResponse.json({ error: "Solo el autor puede editar" }, { status: 403 });

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(updateCommentSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const updateData: Record<string, unknown> = {};
  if (body.content !== undefined) updateData.content = body.content;
  if (body.contentIv !== undefined) updateData.contentIv = body.contentIv;
  if (body.mentions !== undefined) updateData.mentions = JSON.stringify(body.mentions);

  const updated = await db.comment.update({ where: { id: commentId }, data: updateData });
  return NextResponse.json(updated);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string; commentId: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { commentId } = await params;

  const comment = await db.comment.findUnique({ where: { id: commentId } });
  if (!comment) return NextResponse.json({ error: "Comentario no encontrado" }, { status: 404 });
  if (comment.authorId !== auth.userId) return NextResponse.json({ error: "Solo el autor puede borrar" }, { status: 403 });

  await db.comment.delete({ where: { id: commentId } });
  return NextResponse.json({ deleted: true });
}
