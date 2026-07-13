import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const logs = await db.auditLog.findMany({
    where: { userId: auth.userId },
    orderBy: { createdAt: "desc" },
    take: 50,
    select: { id: true, eventCategory: true, createdAt: true, encryptedEvent: true },
  });

  return NextResponse.json({
    activity: logs.map(l => ({
      id: l.id,
      category: l.eventCategory,
      timestamp: l.createdAt,
      encrypted: true,
    })),
    note: "Events are encrypted. Client must decrypt with auditKey to see details.",
  });
}
