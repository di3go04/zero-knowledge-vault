import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { approvalDecisionSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const request = await db.approvalRequest.findUnique({
    where: { id },
    include: {
      requester: { select: { id: true, email: true, name: true } },
      approvedBy: { select: { id: true, email: true, name: true } },
    },
  });
  if (!request) {
    return NextResponse.json({ error: "Approval request not found" }, { status: 404 });
  }

  return NextResponse.json(request);
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

  const validation = validatePayload(approvalDecisionSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.approvalRequest.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Approval request not found" }, { status: 404 });
  }
  if (existing.status !== "pending") {
    return NextResponse.json({ error: `Request is already ${existing.status}` }, { status: 400 });
  }
  if (existing.requesterId === auth.userId) {
    return NextResponse.json({ error: "Cannot approve your own request" }, { status: 403 });
  }

  const updated = await db.approvalRequest.update({
    where: { id },
    data: {
      status: validation.data.decision,
      approvedById: auth.userId,
      approverComment: validation.data.comment ?? null,
    },
    include: {
      requester: { select: { id: true, email: true, name: true } },
      approvedBy: { select: { id: true, email: true, name: true } },
    },
  });

  return NextResponse.json(updated);
}
