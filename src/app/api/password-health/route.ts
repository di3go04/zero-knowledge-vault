import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const shares = await db.secretKeyShare.findMany({
    where: { recipientId: auth.userId },
    include: { secret: true },
  });

  const total = shares.length;
  const owned = shares.filter(s => s.secret.ownerId === auth.userId).length;
  const shared = total - owned;
  const oldSecrets = shares.filter(s => {
    const ageDays = (Date.now() - new Date(s.secret.createdAt).getTime()) / 86400000;
    return ageDays > 90;
  }).length;

  return NextResponse.json({
    totalSecrets: total,
    owned,
    shared,
    oldSecrets,
    healthScore: Math.max(0, 100 - oldSecrets * 5),
    recommendations: oldSecrets > 0 ? ["Consider rotating secrets older than 90 days"] : [],
  });
}
