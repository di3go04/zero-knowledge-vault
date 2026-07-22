import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { logger } from "@/lib/logger";

export async function DELETE(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;
  const { id } = await params;

  const passkey = await db.passkey.findUnique({ where: { id } });
  if (!passkey) {
    return NextResponse.json({ error: "Passkey no encontrada" }, { status: 404 });
  }
  if (passkey.userId !== userId) {
    return NextResponse.json({ error: "No autorizado" }, { status: 403 });
  }

  await db.passkey.delete({ where: { id } });

  logger.info({ userId, passkeyId: id }, "passkey deleted");
  return NextResponse.json({ ok: true });
}
