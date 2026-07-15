import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { db } from "@/lib/db";
import { getWebAuthnConfig } from "@/lib/webauthn-config";
import { z } from "zod";

const beginSchema = z.object({
  email: z.string().email().min(3).max(320),
});

export async function POST(req: Request): Promise<Response> {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400 });
  }

  const parsed = beginSchema.safeParse(body);
  if (!parsed.success) {
    return new Response(JSON.stringify({ error: "Invalid email" }), { status: 400 });
  }

  const user = await db.user.findUnique({
    where: { email: parsed.data.email.toLowerCase().trim() },
    include: {
      webAuthnCredentials: { select: { credentialId: true, transports: true } },
    },
  });

  if (!user || user.webAuthnCredentials.length === 0) {
    return new Response(JSON.stringify({ error: "No WebAuthn credentials found" }), { status: 404 });
  }

  const { rpId } = getWebAuthnConfig();

  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: user.webAuthnCredentials.map((c) => ({
      id: Buffer.from(c.credentialId, "base64url"),
      type: "public-key" as const,
      transports: JSON.parse(c.transports) as AuthenticatorTransport[],
    })),
    userVerification: "preferred",
  });

  return new Response(
    JSON.stringify({ ...options, userId: user.id }),
    { headers: { "Content-Type": "application/json" } },
  );
}