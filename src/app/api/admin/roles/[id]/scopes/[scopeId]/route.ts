import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string; scopeId: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id, scopeId } = await params;
  const scope = await db.roleScope.findFirst({ where: { id: scopeId, roleId: id } });
  if (!scope) {
    return NextResponse.json({ error: "Scope not found" }, { status: 404 });
  }

  await db.roleScope.delete({ where: { id: scopeId } });
  return NextResponse.json({}, { status: 204 });
}
