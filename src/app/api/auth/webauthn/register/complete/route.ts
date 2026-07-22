import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { verifyRegistrationCredential, consumeChallenge } from "@/lib/webauthn";
import { logger } from "@/lib/logger";
import { z } from "zod";

const completeSchema = z.object({
  credential: z.object({
    id: z.string().min(1),
    rawId: z.string().min(1),
    response: z.object({
      clientDataJSON: z.string().min(1),
      attestationObject: z.string().min(1),
      transports: z.array(z.string()).optional(),
    }),
  }),
  deviceName: z.string().max(80).optional(),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = completeSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json(
      { error: validation.error.issues[0]?.message ?? "Validación fallida" },
      { status: 400 },
    );
  }

  const { credential, deviceName } = validation.data;

  // The challenge is embedded in clientDataJSON; we need to extract it
  // to consume it from the store
  let clientData: { challenge: string };
  try {
    clientData = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, "base64url").toString("utf8"),
    );
  } catch {
    return NextResponse.json({ error: "Invalid clientDataJSON" }, { status: 400 });
  }

  const challengeEntry = consumeChallenge(clientData.challenge);
  if (!challengeEntry) {
    return NextResponse.json(
      { error: "Challenge inválido, expirado o ya usado" },
      { status: 400 },
    );
  }

  if (challengeEntry.userId !== userId) {
    return NextResponse.json({ error: "Challenge no pertenece a este usuario" }, { status: 403 });
  }

  const result = verifyRegistrationCredential(credential, clientData.challenge);
  if (typeof result === "string") {
    return NextResponse.json({ error: result }, { status: 400 });
  }

  // Check for duplicate credentialId
  const existing = await db.passkey.findUnique({
    where: { credentialId: result.credentialId },
  });
  if (existing) {
    return NextResponse.json(
      { error: "Esta passkey ya está registrada" },
      { status: 409 },
    );
  }

  const passkey = await db.passkey.create({
    data: {
      userId,
      credentialId: result.credentialId,
      publicKey: result.publicKey,
      algorithm: result.algorithm,
      aaguid: result.aaguid,
      transports: result.transports,
      backedUp: result.backedUp,
      counter: result.counter,
      deviceName: deviceName ?? null,
    },
  });

  logger.info({ userId, passkeyId: passkey.id }, "passkey registered");
  return NextResponse.json({
    ok: true,
    id: passkey.id,
    credentialId: passkey.credentialId,
    createdAt: passkey.createdAt,
  });
}
