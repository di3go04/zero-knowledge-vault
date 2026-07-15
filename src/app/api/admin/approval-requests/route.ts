import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { approvalRequestSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const status = req.nextUrl.searchParams.get("status");

  const where: any = {};
  if (status && ["pending", "approved", "rejected", "cancelled"].includes(status)) {
    where.status = status;
  }

  const requests = await db.approvalRequest.findMany({
    where,
    include: {
      requester: { select: { id: true, email: true, name: true } },
      approvedBy: { select: { id: true, email: true, name: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ requests });
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

  const validation = validatePayload(approvalRequestSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const approvalRequest = await db.approvalRequest.create({
    data: {
      requesterId: auth.userId,
      ...validation.data,
      resourceId: validation.data.resourceId ?? null,
    },
    include: {
      requester: { select: { id: true, email: true, name: true } },
    },
  });

  return NextResponse.json(approvalRequest, { status: 201 });
}
