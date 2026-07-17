import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function GET(req: NextRequest, { params }: { params: Promise<{ token: string }> }) {
  const { token } = await params;

  const share = await db.oneTimeShare.findUnique({ where: { token } });
  if (!share) return NextResponse.json({ error: "Share no encontrado" }, { status: 404 });
  if (share.status !== "active") return NextResponse.json({ error: "Share ya fue canjeado o expiró" }, { status: 410 });
  if (share.expiresAt < new Date()) {
    await db.oneTimeShare.update({ where: { id: share.id }, data: { status: "expired" } });
    return NextResponse.json({ error: "Share expiró" }, { status: 410 });
  }

  const newViews = share.currentViews + 1;
  const newStatus = newViews >= share.maxViews ? "claimed" : "active";

  const updated = await db.oneTimeShare.update({
    where: { id: share.id },
    data: { currentViews: newViews, status: newStatus },
  });

  return NextResponse.json({
    secretId: updated.secretId,
    wrappedSymmetricKey: updated.wrappedSymmetricKey,
    currentViews: updated.currentViews,
    maxViews: updated.maxViews,
    status: updated.status,
  });
}
