import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { breakGlassSchema, validatePayload } from "@/lib/validation-schemas";
import { randomBytes } from "node:crypto";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const status = req.nextUrl.searchParams.get("status");

  const where: any = {};
  if (status && ["pending", "approved", "denied", "expired"].includes(status)) {
    where.status = status;
  }

  const accesses = await db.breakGlassAccess.findMany({
    where,
    include: {
      user: { select: { id: true, email: true, name: true } },
      approver: { select: { id: true, email: true, name: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ accesses });
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

  const validation = validatePayload(breakGlassSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const access = await db.breakGlassAccess.create({
    data: {
      userId: auth.userId,
      reason: validation.data.reason,
      status: "pending",
      expiresAt: new Date(Date.now() + 3600_000),
    },
    include: {
      user: { select: { id: true, email: true, name: true } },
    },
  });

  return NextResponse.json(access, { status: 201 });
}
