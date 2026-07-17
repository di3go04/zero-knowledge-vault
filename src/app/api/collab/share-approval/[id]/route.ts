import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { shareApprovalDecisionSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;
  const { id } = await params;

  const approval = await db.shareApproval.findUnique({ where: { id } });
  if (!approval) return NextResponse.json({ error: "Solicitud no encontrada" }, { status: 404 });
  if (approval.approverId !== userId) return NextResponse.json({ error: "Solo el approver puede decidir" }, { status: 403 });
  if (approval.status !== "pending") return NextResponse.json({ error: "Ya fue decidida" }, { status: 400 });

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(shareApprovalDecisionSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { decision, wrappedSymmetricKey, comment } = validation.data;

  const updateData: Record<string, unknown> = { status: decision, approverComment: comment ?? null };
  if (decision === "approved" && wrappedSymmetricKey) {
    updateData.wrappedSymmetricKey = wrappedSymmetricKey;
  }

  const updated = await db.shareApproval.update({ where: { id }, data: updateData });

  if (decision === "approved" && approval.recipientId && wrappedSymmetricKey) {
    await db.secretKeyShare.upsert({
      where: { secretId_recipientId: { secretId: approval.secretId, recipientId: approval.recipientId } },
      update: { wrappedSymmetricKey },
      create: { secretId: approval.secretId, recipientId: approval.recipientId, wrappedSymmetricKey },
    });
  }

  await db.notification.create({
    data: {
      userId: approval.requesterId,
      type: "approval",
      title: `Solicitud de share ${decision === "approved" ? "aprobada" : "rechazada"}`,
      data: JSON.stringify({ approvalId: id, secretId: approval.secretId, decision }),
    },
  });

  return NextResponse.json(updated);
}
