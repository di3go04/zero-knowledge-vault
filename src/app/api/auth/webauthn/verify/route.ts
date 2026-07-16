import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { z } from "zod";

const verifySchema = z.object({
  credentialId: z.string(),
  publicKey: z.string(),
  counter: z.number(),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const body = await req.json();
  const validation = verifySchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
  }

  const { credentialId, publicKey, counter } = validation.data;

  await db.device.create({
    data: {
      userId,
      deviceName: `WebAuthn-${credentialId.slice(0, 8)}`,
      publicKeyECDH: publicKey,
      publicKeyECDHFingerprint: credentialId,
      wrappedPrivateKeyForDevice: "",
      wrappedPrivateKeyIv: "",
    },
  });

  return NextResponse.json({ verified: true });
}
