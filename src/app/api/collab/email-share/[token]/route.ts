import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  const share = await db.emailShare.findUnique({ where: { token } });
  if (!share) return NextResponse.json({ error: "Share no encontrado" }, { status: 404 });
  if (share.status !== "pending") return NextResponse.json({ error: `Share ${share.status}` }, { status: 410 });
  if (share.expiresAt < new Date()) {
    await db.emailShare.update({ where: { id: share.id }, data: { status: "expired" } });
    return NextResponse.json({ error: "Share expiró" }, { status: 410 });
  }

  const auth = await requireAuth(req);
  if (!auth.ok) {
    return NextResponse.json({
      requiresAuth: true,
      message: "Debes iniciar sesión para reclamar este share",
      email: share.recipientEmail,
      token,
    }, { status: 401 });
  }

  const userId = auth.userId;
  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user || user.email?.toLowerCase() !== share.recipientEmail.toLowerCase()) {
    return NextResponse.json({ error: "Este share fue enviado a otro email" }, { status: 403 });
  }

  await db.emailShare.update({
    where: { id: share.id },
    data: { status: "claimed", claimedAt: new Date() },
  });

  return NextResponse.json({
    secretId: share.secretId,
    message: share.message,
    status: "claimed",
    note: "El share fue reclamado. El owner debe compartir la wrappedSymmetricKey para que puedas descifrar el secreto.",
  });
}
