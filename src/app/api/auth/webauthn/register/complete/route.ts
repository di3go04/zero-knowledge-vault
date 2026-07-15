import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { getWebAuthnConfig, base64urlencode } from "@/lib/webauthn-config";

export async function POST(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400 });
  }

  const { credential, deviceName } = body;
  if (!credential) {
    return new Response(JSON.stringify({ error: "Missing credential" }), { status: 400 });
  }

  const { rpId, origin } = getWebAuthnConfig();

  const verification = await verifyRegistrationResponse({
    credential,
    expectedRPID: rpId,
    expectedOrigin: [origin],
  });

  if (!verification.verified || !verification.registrationInfo) {
    return new Response(JSON.stringify({ error: "Registration verification failed" }), { status: 400 });
  }

  const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

  const credentialIdB64url = base64urlencode(new Uint8Array(credentialID));
  const publicKeyB64url = base64urlencode(new Uint8Array(credentialPublicKey));

  await db.webAuthnCredential.create({
    data: {
      id: credentialIdB64url,
      userId: auth.userId,
      credentialId: credentialIdB64url,
      publicKey: publicKeyB64url,
      counter: BigInt(counter),
      transports: JSON.stringify(credential.response?.transports || ["internal"]),
      deviceName: deviceName || "WebAuthn Device",
      credentialType: body.credential?.response?.authenticatorAttachment === "cross-platform" ? "cross-platform" : "platform",
    },
  });

  return new Response(JSON.stringify({ verified: true, credentialId: credentialIdB64url }), {
    headers: { "Content-Type": "application/json" },
  });
}