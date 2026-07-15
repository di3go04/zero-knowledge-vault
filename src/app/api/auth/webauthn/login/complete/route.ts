import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { db } from "@/lib/db";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { issueSessionToken } from "@/lib/session-token";

export async function POST(req: Request): Promise<Response> {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400 });
  }

  const { credential, userId } = body;
  if (!credential || !userId) {
    return new Response(JSON.stringify({ error: "Missing credential or userId" }), { status: 400 });
  }

  const user = await db.user.findUnique({
    where: { id: userId },
    include: { webAuthnCredentials: true, keyMaterial: true },
  });
  if (!user) {
    return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
  }

  const cred = user.webAuthnCredentials.find(
    (c) => c.credentialId === credential.id,
  );
  if (!cred) {
    return new Response(JSON.stringify({ error: "Credential not found" }), { status: 404 });
  }

  const { rpId, origin } = getWebAuthnConfig();

  const verification = await verifyAuthenticationResponse({
    credential,
    expectedRPID: rpId,
    expectedOrigin: [origin],
    credential: {
      id: cred.credentialId,
      publicKey: Buffer.from(cred.publicKey, "base64url"),
      counter: Number(cred.counter),
      transports: JSON.parse(cred.transports) as AuthenticatorTransport[],
    },
  });

  if (!verification.verified) {
    return new Response(JSON.stringify({ error: "Authentication failed" }), { status: 401 });
  }

  await db.webAuthnCredential.update({
    where: { id: cred.id },
    data: { counter: BigInt(verification.authenticationInfo.newCounter), lastUsedAt: new Date() },
  });

  const token = issueSessionToken(user.id);
  const sessionExp = Math.floor(Date.now() / 1000) + 3600;

  return new Response(
    JSON.stringify({
      verified: true,
      userId: user.id,
      email: user.email,
      name: user.name,
      sessionToken: token,
      expiresAt: sessionExp,
      kdfAlgorithm: user.keyMaterial?.kdfAlgorithm,
      kdfSalt: user.keyMaterial?.kdfSalt,
      kdfIterations: user.keyMaterial?.kdfIterations,
      kdfMemoryKiB: user.keyMaterial?.kdfMemoryKiB,
      kdfParallelism: user.keyMaterial?.kdfParallelism,
      encryptedPrivateKeyJwk: user.keyMaterial?.encryptedPrivateKeyJwk,
      privateKeyIv: user.keyMaterial?.privateKeyIv,
      publicKeyJwk: user.keyMaterial?.publicKeyJwk ? JSON.parse(user.keyMaterial.publicKeyJwk) : null,
    }),
    { headers: { "Content-Type": "application/json" } },
  );
}