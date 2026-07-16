import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const activeUsers = await db.user.count();
  const activeSecrets = await db.secret.count();
  const activeShares = await db.secretKeyShare.count();

  return NextResponse.json({
    activeUsers,
    activeSecrets,
    activeShares,
    adoptionRate: activeUsers > 0 ? (activeSecrets / activeUsers).toFixed(2) : "0",
    note: "Adoption report — secrets per user ratio.",
  });
}
