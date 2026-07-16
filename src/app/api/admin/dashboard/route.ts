import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const users = await db.user.count();
  const secrets = await db.secret.count();
  const shares = await db.secretKeyShare.count();
  const devices = await db.device.count();
  const logs = await db.auditLog.count();

  return NextResponse.json({
    stats: { users, secrets, shares, devices, auditLogs: logs },
    timestamp: new Date().toISOString(),
  });
}
