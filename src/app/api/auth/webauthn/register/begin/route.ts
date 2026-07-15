import { generateRegistrationOptions } from "@simplewebauthn/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { getWebAuthnConfig } from "@/lib/webauthn-config";

export async function POST(req: Request): Promise<Response> {
  const auth = await requireAuth(req);
  if (!auth.authenticated) return auth.response;

  const user = await db.user.findUnique({
    where: { id: auth.userId },
    include: {
      webAuthnCredentials: { select: { credentialId: true } },
    },
  });
  if (!user) {
    return new Response(JSON.stringify({ error: "User not found" }), { status: 404 });
  }

  const { rpName, rpId } = getWebAuthnConfig();

  const options = await generateRegistrationOptions({
    rpName,
    rpID: rpId,
    userName: user.email,
    userDisplayName: user.name || user.email,
    attestationType: "none",
    excludeCredentials: user.webAuthnCredentials.map((c) => ({
      id: Buffer.from(c.credentialId, "base64url"),
      type: "public-key" as const,
      transports: ["usb", "nfc", "ble", "internal"] as AuthenticatorTransport[],
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  });

  return new Response(JSON.stringify(options), {
    headers: { "Content-Type": "application/json" },
  });
}