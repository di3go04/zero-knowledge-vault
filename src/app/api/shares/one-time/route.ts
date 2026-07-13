import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { randomBytes } from "node:crypto";
import { z } from "zod";

const oneTimeSchema = z.object({
  secretId: z.string(),
  ttlHours: z.number().min(1).max(168).default(24),
  maxViews: z.number().min(1).max(10).default(1),
});

const oneTimeShares = new Map<string, {
  secretId: string;
  ownerId: string;
  token: string;
  expiresAt: Date;
  viewsRemaining: number;
  wrappedKey: string;
  encryptedTitle: string;
  titleIv: string;
  encryptedData: string;
  dataIv: string;
}>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = oneTimeSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
  }

  const { secretId, ttlHours, maxViews } = validation.data;

  const share = await db.secretKeyShare.findUnique({
    where: { secretId_recipientId: { secretId, recipientId: auth.userId } },
    include: { secret: true },
  });
  if (!share) {
    return NextResponse.json({ error: "Access denied" }, { status: 403 });
  }

  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000);

  oneTimeShares.set(token, {
    secretId,
    ownerId: auth.userId,
    token,
    expiresAt,
    viewsRemaining: maxViews,
    wrappedKey: share.wrappedSymmetricKey,
    encryptedTitle: share.secret.encryptedTitle,
    titleIv: share.secret.titleIv,
    encryptedData: share.secret.encryptedData,
    dataIv: share.secret.dataIv,
  });

  return NextResponse.json({
    url: `${process.env.APP_URL || "http://localhost:3000"}/?oneTime=${token}`,
    expiresAt: expiresAt.toISOString(),
    maxViews,
  });
}

export async function GET(req: NextRequest) {
  const token = req.nextUrl.searchParams.get("token");
  if (!token) return NextResponse.json({ error: "Token required" }, { status: 400 });

  const share = oneTimeShares.get(token);
  if (!share) return NextResponse.json({ error: "Invalid or expired" }, { status: 404 });

  if (new Date() > share.expiresAt) {
    oneTimeShares.delete(token);
    return NextResponse.json({ error: "Expired" }, { status: 410 });
  }

  share.viewsRemaining--;
  if (share.viewsRemaining <= 0) {
    oneTimeShares.delete(token);
  }

  return NextResponse.json({
    encryptedTitle: share.encryptedTitle,
    titleIv: share.titleIv,
    encryptedData: share.encryptedData,
    dataIv: share.dataIv,
    wrappedKey: share.wrappedKey,
    viewsRemaining: share.viewsRemaining,
  });
}
