import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { generateChallenge } from "@/lib/webauthn";
import { db } from "@/lib/db";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const challenge = generateChallenge();
  const user = await db.user.findUnique({ where: { id: userId } });

  const options = {
    challenge,
    rp: { name: "ZK Vault", id: req.headers.get("host")?.split(":")[0] || "localhost" },
    user: { id: userId, name: user?.email || "", displayName: user?.name || user?.email || "" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
    timeout: 60000,
    attestation: "none",
  };

  await db.userKeyMaterial.update({
    where: { userId },
    data: { popSignature: challenge },
  });

  return NextResponse.json(options);
}
