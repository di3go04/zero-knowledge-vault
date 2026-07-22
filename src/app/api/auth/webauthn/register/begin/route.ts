import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { generateRegistrationOptions } from "@/lib/webauthn";
import { logger } from "@/lib/logger";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const user = await db.user.findUnique({
    where: { id: userId },
    select: { email: true, name: true },
  });
  if (!user) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  const existingPasskeys = await db.passkey.findMany({
    where: { userId },
    select: { credentialId: true, transports: true },
  });

  const options = generateRegistrationOptions(
    userId,
    user.email,
    user.name ?? user.email,
    existingPasskeys.map((p) => p.credentialId),
  );

  logger.info({ userId }, "webauthn registration started");
  return NextResponse.json(options);
}
