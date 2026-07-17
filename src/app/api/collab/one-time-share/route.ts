import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { oneTimeShareSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";
import { randomBytes } from "node:crypto";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(oneTimeShareSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { secretId, wrappedSymmetricKey, maxViews, expiresInHours } = validation.data;

  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId !== userId) return NextResponse.json({ error: "Solo el owner puede crear shares" }, { status: 403 });

  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + expiresInHours * 3600_000);

  const share = await db.oneTimeShare.create({
    data: { secretId, ownerId: userId, token, wrappedSymmetricKey, maxViews, expiresAt },
  });

  return NextResponse.json({
    id: share.id,
    token: share.token,
    maxViews: share.maxViews,
    expiresAt: share.expiresAt,
  }, { status: 201 });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const [shares, total] = await Promise.all([
    db.oneTimeShare.findMany({
      where: { ownerId: userId },
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.oneTimeShare.count({ where: { ownerId: userId } }),
  ]);

  return NextResponse.json({ shares, pagination: { offset, limit, total, hasMore: offset + limit < total } });
}
