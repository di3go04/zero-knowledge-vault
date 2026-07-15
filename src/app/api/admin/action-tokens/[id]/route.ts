import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const token = await db.userActionToken.findUnique({ where: { id } });
  if (!token) {
    return NextResponse.json({ error: "Action token not found" }, { status: 404 });
  }

  return NextResponse.json(token);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const token = await db.userActionToken.findUnique({ where: { id } });
  if (!token) {
    return NextResponse.json({ error: "Action token not found" }, { status: 404 });
  }

  await db.userActionToken.delete({ where: { id } });
  return NextResponse.json({}, { status: 204 });
}
