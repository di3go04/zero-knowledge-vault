import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { userActionTokenSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);
  const userId = req.nextUrl.searchParams.get("userId");
  const action = req.nextUrl.searchParams.get("action");
  const status = req.nextUrl.searchParams.get("status");

  const where: Record<string, unknown> = {};
  if (userId) where.userId = userId;
  if (action) where.action = action;
  if (status) where.status = status;

  const tokens = await db.userActionToken.findMany({
    where,
    skip: offset,
    take: limit,
    orderBy: { createdAt: "desc" },
  });

  const total = await db.userActionToken.count({ where });

  return NextResponse.json({ tokens, total, offset, limit });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(userActionTokenSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const rawToken = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + validation.data.expiresInHours * 3600_000);

  const token = await db.userActionToken.create({
    data: {
      userId: validation.data.userId,
      token: rawToken,
      action: validation.data.action,
      payload: validation.data.payload || null,
      expiresAt,
    },
  });

  return NextResponse.json(
    {
      id: token.id,
      userId: token.userId,
      action: token.action,
      token: rawToken,
      expiresAt: token.expiresAt,
      createdAt: token.createdAt,
    },
    { status: 201 },
  );
}
