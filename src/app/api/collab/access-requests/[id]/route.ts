import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { accessRequestDecisionSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;
  const { id } = await params;

  const accessRequest = await db.accessRequest.findUnique({ where: { id } });
  if (!accessRequest) return NextResponse.json({ error: "Solicitud no encontrada" }, { status: 404 });

  const secret = await db.secret.findUnique({ where: { id: accessRequest.secretId }, select: { ownerId: true } });
  if (!secret || secret.ownerId !== userId) return NextResponse.json({ error: "Solo el owner del secreto puede decidir" }, { status: 403 });
  if (accessRequest.status !== "pending") return NextResponse.json({ error: "Solicitud ya fue procesada" }, { status: 400 });

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(accessRequestDecisionSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { decision, wrappedSymmetricKey, comment } = validation.data;

  const updated = await db.accessRequest.update({
    where: { id },
    data: { status: decision, approverId: userId, approverComment: comment ?? null },
  });

  if (decision === "approved" && wrappedSymmetricKey) {
    await db.secretKeyShare.upsert({
      where: { secretId_recipientId: { secretId: accessRequest.secretId, recipientId: accessRequest.requesterId } },
      update: { wrappedSymmetricKey },
      create: { secretId: accessRequest.secretId, recipientId: accessRequest.requesterId, wrappedSymmetricKey },
    });
  }

  await db.notification.create({
    data: {
      userId: accessRequest.requesterId,
      type: "access-request",
      title: `Solicitud de acceso ${decision === "approved" ? "aprobada" : "denegada"}`,
      data: JSON.stringify({ accessRequestId: id, secretId: accessRequest.secretId, decision }),
    },
  });

  return NextResponse.json(updated);
}
