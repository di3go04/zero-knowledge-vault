import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { logger } from "@/lib/logger";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const passkeys = await db.passkey.findMany({
    where: { userId },
    select: {
      id: true,
      credentialId: true,
      algorithm: true,
      aaguid: true,
      transports: true,
      deviceName: true,
      createdAt: true,
      lastUsedAt: true,
      backedUp: true,
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ passkeys });
}
