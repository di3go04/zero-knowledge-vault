import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { verifyActionTokenSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(verifyActionTokenSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const token = await db.userActionToken.findUnique({
    where: { token: validation.data.token },
  });

  if (!token) {
    return NextResponse.json({ error: "Token not found" }, { status: 404 });
  }

  if (token.status !== "pending") {
    return NextResponse.json(
      { error: `Token is already ${token.status}`, status: token.status },
      { status: 400 },
    );
  }

  if (token.expiresAt < new Date()) {
    await db.userActionToken.update({
      where: { id: token.id },
      data: { status: "expired" },
    });
    return NextResponse.json({ error: "Token has expired", status: "expired" }, { status: 400 });
  }

  await db.userActionToken.update({
    where: { id: token.id },
    data: { status: "used", usedAt: new Date() },
  });

  return NextResponse.json({
    verified: true,
    userId: token.userId,
    action: token.action,
    payload: token.payload,
  });
}
