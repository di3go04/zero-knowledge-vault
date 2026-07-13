import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const genSchema = z.object({ keyType: z.enum(["ed25519", "rsa"]).default("ed25519") });

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = genSchema.safeParse(body);
  if (!validation.success) return NextResponse.json({ error: "Invalid keyType" }, { status: 400 });

  const { generateSSHKeyPair } = await import("@/lib/ssh-keys");
  const keyPair = await generateSSHKeyPair(validation.data.keyType);
  return NextResponse.json(keyPair);
}
