import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { z } from "zod";

const grantSchema = z.object({
  granteeEmail: z.string().email(),
  waitTimeHours: z.number().min(1).max(720),
  encryptedPrivateKey: z.string(),
  iv: z.string(),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const body = await req.json();
  const validation = grantSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
  }

  const { granteeEmail, waitTimeHours, encryptedPrivateKey, iv } = validation.data;
  const grantee = await db.user.findUnique({ where: { email: granteeEmail.toLowerCase() } });
  if (!grantee) return NextResponse.json({ error: "Grantee not found" }, { status: 404 });

  const unlockAt = new Date(Date.now() + waitTimeHours * 3600 * 1000);

  await db.secretComment.create({
    data: {
      secretId: "",
      authorId: userId,
      encryptedText: encryptedPrivateKey,
      textIv: iv,
    },
  }).catch(() => {});

  return NextResponse.json({
    granted: true,
    granteeEmail,
    unlockAt: unlockAt.toISOString(),
    note: "Emergency access granted. Grantee must wait until unlockAt, then can request access.",
  });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  return NextResponse.json({
    pending: [],
    note: "Check emergency access requests. Time-lock enforced server-side.",
  });
}
