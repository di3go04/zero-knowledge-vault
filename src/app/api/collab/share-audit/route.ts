import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { shareAuditEventSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(shareAuditEventSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { secretId, action, targetId, metadata } = validation.data;

  const event = await db.shareAuditEvent.create({
    data: {
      secretId,
      actorId: userId,
      action,
      targetId: targetId ?? null,
      metadata: metadata ?? null,
      ipAddress: req.headers.get("x-forwarded-for") ?? req.headers.get("x-real-ip") ?? null,
      userAgent: req.headers.get("user-agent") ?? null,
    },
  });

  return NextResponse.json(event, { status: 201 });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);
  const action = req.nextUrl.searchParams.get("action");
  const secretId = req.nextUrl.searchParams.get("secretId");

  const where: Record<string, unknown> = { actorId: userId };
  if (action) where.action = action;
  if (secretId) where.secretId = secretId;

  const [events, total] = await Promise.all([
    db.shareAuditEvent.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.shareAuditEvent.count({ where }),
  ]);

  return NextResponse.json({ events, pagination: { offset, limit, total, hasMore: offset + limit < total } });
}
