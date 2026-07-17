import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { secretTagSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;

  const secretTags = await db.secretTag.findMany({
    where: { secretId: id },
    include: { tag: true },
  });

  return NextResponse.json({ tags: secretTags.map((st) => st.tag) });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;

  const secret = await db.secret.findUnique({ where: { id } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId !== auth.userId) return NextResponse.json({ error: "Solo el owner puede etiquetar" }, { status: 403 });

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(secretTagSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { tagId } = validation.data;

  const tag = await db.tag.findUnique({ where: { id: tagId } });
  if (!tag) return NextResponse.json({ error: "Tag no encontrado" }, { status: 404 });

  const existing = await db.secretTag.findUnique({
    where: { secretId_tagId: { secretId: id, tagId } },
  });
  if (existing) return NextResponse.json({ error: "Tag ya asignado" }, { status: 409 });

  const secretTag = await db.secretTag.create({ data: { secretId: id, tagId } });
  return NextResponse.json(secretTag, { status: 201 });
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;
  const url = req.nextUrl;
  const tagId = url.searchParams.get("tagId");
  if (!tagId) return NextResponse.json({ error: "tagId requerido" }, { status: 400 });

  await db.secretTag.deleteMany({ where: { secretId: id, tagId } });
  return NextResponse.json({ deleted: true });
}
