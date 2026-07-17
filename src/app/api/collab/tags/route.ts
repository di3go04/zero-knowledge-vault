import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { tagSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const q = req.nextUrl.searchParams.get("q") ?? "";
  const limit = Math.min(parseInt(req.nextUrl.searchParams.get("limit") ?? "100", 10), 200);

  const where: Record<string, unknown> = {};
  if (q) where.name = { contains: q };

  const tags = await db.tag.findMany({ where, orderBy: { name: "asc" }, take: limit });
  return NextResponse.json({ tags });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(tagSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { name, color, favorite } = validation.data;

  const existing = await db.tag.findUnique({ where: { name } });
  if (existing) return NextResponse.json({ error: "El tag ya existe" }, { status: 409 });

  const tag = await db.tag.create({
    data: { name, color: color ?? "#6366f1", favorite: favorite ?? false, createdBy: userId },
  });

  return NextResponse.json(tag, { status: 201 });
}
