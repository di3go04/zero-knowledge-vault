import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { randomBytes } from "node:crypto";
import { z } from "zod";

const tempVaultSchema = z.object({
  encryptedData: z.string(),
  iv: z.string(),
  ttlMinutes: z.number().min(1).max(1440).default(60),
});

const tempVaults = new Map<string, { data: string; iv: string; expiresAt: Date }>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = tempVaultSchema.safeParse(body);
  if (!validation.success) return NextResponse.json({ error: "Invalid" }, { status: 400 });

  const token = randomBytes(32).toString("hex");
  tempVaults.set(token, {
    data: validation.data.encryptedData,
    iv: validation.data.iv,
    expiresAt: new Date(Date.now() + validation.data.ttlMinutes * 60000),
  });

  return NextResponse.json({
    url: `${process.env.APP_URL || "http://localhost:3000"}/?tempVault=${token}`,
    expiresAt: tempVaults.get(token)!.expiresAt.toISOString(),
  });
}

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get("token");
  if (!token) return NextResponse.json({ error: "Token required" }, { status: 400 });

  const vault = tempVaults.get(token);
  if (!vault || new Date() > vault.expiresAt) {
    if (vault) tempVaults.delete(token);
    return NextResponse.json({ error: "Expired or invalid" }, { status: 410 });
  }

  tempVaults.delete(token);
  return NextResponse.json({ encryptedData: vault.data, iv: vault.iv });
}
