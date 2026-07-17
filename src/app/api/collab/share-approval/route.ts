import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { shareApprovalRequestSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const requesterId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(shareApprovalRequestSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { secretId, approverId, recipientId, reason } = validation.data;

  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId !== requesterId) return NextResponse.json({ error: "Solo el owner puede solicitar aprobación" }, { status: 403 });

  const approver = await db.user.findUnique({ where: { id: approverId } });
  if (!approver) return NextResponse.json({ error: "Approver no encontrado" }, { status: 404 });

  const approval = await db.shareApproval.create({
    data: { secretId, requesterId, approverId, recipientId, reason },
  });

  await db.notification.create({
    data: {
      userId: approverId,
      type: "approval",
      title: "Solicitud de aprobación para compartir",
      body: reason ?? null,
      data: JSON.stringify({ approvalId: approval.id, secretId }),
    },
  });

  return NextResponse.json(approval, { status: 201 });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const status = req.nextUrl.searchParams.get("status");

  const where: Record<string, unknown> = {
    OR: [{ requesterId: userId }, { approverId: userId }],
  };
  if (status) where.status = status;

  const approvals = await db.shareApproval.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: 50,
  });

  return NextResponse.json({ approvals });
}
