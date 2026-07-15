import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { breakGlassDecisionSchema, validatePayload } from "@/lib/validation-schemas";
import { randomBytes } from "node:crypto";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const access = await db.breakGlassAccess.findUnique({
    where: { id },
    include: {
      user: { select: { id: true, email: true, name: true } },
      approver: { select: { id: true, email: true, name: true } },
    },
  });
  if (!access) {
    return NextResponse.json({ error: "Break-glass access not found" }, { status: 404 });
  }

  return NextResponse.json(access);
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(breakGlassDecisionSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.breakGlassAccess.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Break-glass access not found" }, { status: 404 });
  }
  if (existing.status !== "pending") {
    return NextResponse.json({ error: `Request is already ${existing.status}` }, { status: 400 });
  }
  if (existing.userId === auth.userId) {
    return NextResponse.json({ error: "Cannot approve your own break-glass request" }, { status: 403 });
  }

  const updateData: any = {
    approverId: auth.userId,
    status: validation.data.decision === "approved" ? "approved" : "denied",
    approvedAt: new Date(),
  };

  if (validation.data.decision === "approved") {
    updateData.accessToken = randomBytes(32).toString("hex");
  }

  const updated = await db.breakGlassAccess.update({
    where: { id },
    data: updateData,
    include: {
      user: { select: { id: true, email: true, name: true } },
      approver: { select: { id: true, email: true, name: true } },
    },
  });

  return NextResponse.json(updated);
}
