import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { verifyLoginAssertion, consumeChallenge } from "@/lib/webauthn";
import { issueSessionToken, SESSION_TTL } from "@/lib/session-token";
import { logger } from "@/lib/logger";
import { z } from "zod";

const loginCompleteSchema = z.object({
  credential: z.object({
    id: z.string().min(1),
    rawId: z.string().min(1),
    response: z.object({
      clientDataJSON: z.string().min(1),
      authenticatorData: z.string().min(1),
      signature: z.string().min(1),
      userHandle: z.string().optional(),
    }),
  }),
});

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = loginCompleteSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json(
      { error: validation.error.issues[0]?.message ?? "Validación fallida" },
      { status: 400 },
    );
  }

  const { credential } = validation.data;

  // Extract challenge from clientDataJSON
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

  // Look up the credential in the database
  const rawIdBytes = Buffer.from(credential.rawId, "base64url");
  const credentialIdB64 = rawIdBytes.toString("base64url");

  const storedPasskey = await db.passkey.findUnique({
    where: { credentialId: credentialIdB64 },
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  if (!storedPasskey) {
    return NextResponse.json(
      { error: "Passkey no encontrada" },
      { status: 404 },
    );
  }

  // Verify user matches
  if (storedPasskey.userId !== challengeEntry.userId) {
    return NextResponse.json(
      { error: "La passkey no pertenece al usuario del challenge" },
      { status: 403 },
    );
  }

  const result = verifyLoginAssertion(
    credential,
    clientData.challenge,
    {
      publicKey: storedPasskey.publicKey,
      counter: storedPasskey.counter,
      credentialId: credentialIdB64,
    },
  );

  if (typeof result === "string") {
    return NextResponse.json({ error: result }, { status: 400 });
  }

  // Update counter and lastUsedAt
  await db.passkey.update({
    where: { id: storedPasskey.id },
    data: {
      counter: result.counter,
      lastUsedAt: new Date(),
    },
  });

  // Get the full user data for login response
  const user = await db.user.findUnique({
    where: { id: storedPasskey.userId },
    include: { keyMaterial: true },
  });

  if (!user || !user.keyMaterial) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  const km = user.keyMaterial;
  const sessionToken = issueSessionToken(user.id);
  const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL;

  logger.info({ userId: user.id }, "webauthn login completed");

  return NextResponse.json({
    userId: user.id,
    email: user.email,
    name: user.name,
    kdfAlgorithm: km.kdfAlgorithm,
    kdfSalt: km.kdfSalt,
    kdfIterations: km.kdfIterations,
    kdfMemoryKiB: km.kdfMemoryKiB,
    kdfParallelism: km.kdfParallelism,
    encryptedPrivateKeyJwk: km.encryptedPrivateKeyJwk,
    privateKeyIv: km.privateKeyIv,
    encryptedMlKemPrivateKey: km.encryptedMlKemPrivateKey,
    mlKemPrivateKeyIv: km.mlKemPrivateKeyIv,
    mlKemPublicKey: km.mlKemPublicKey,
    publicKeyJwk: JSON.parse(km.publicKeyJwk),
    publicKeyFingerprint: km.publicKeyFingerprint,
    sessionToken,
    expiresAt,
    isDecoy: false,
    passkeyVerified: true,
  });
}
