import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const exportRecord = await db.eDiscoveryExport.findUnique({ where: { id } });
  if (!exportRecord) {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  return NextResponse.json(exportRecord);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const exportRecord = await db.eDiscoveryExport.findUnique({ where: { id } });
  if (!exportRecord) {
    return NextResponse.json({ error: "Export not found" }, { status: 404 });
  }

  await db.eDiscoveryExport.delete({ where: { id } });
  return NextResponse.json({}, { status: 204 });
}
