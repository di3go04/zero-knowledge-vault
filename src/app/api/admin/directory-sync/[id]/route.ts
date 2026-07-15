import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { directorySyncConfigUpdateSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const config = await db.directorySyncConfig.findUnique({ where: { id } });
  if (!config) {
    return NextResponse.json({ error: "Directory sync config not found" }, { status: 404 });
  }

  return NextResponse.json(config);
}

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(directorySyncConfigUpdateSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.directorySyncConfig.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Directory sync config not found" }, { status: 404 });
  }

  const config = await db.directorySyncConfig.update({ where: { id }, data: validation.data });

  return NextResponse.json(config);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const config = await db.directorySyncConfig.findUnique({ where: { id } });
  if (!config) {
    return NextResponse.json({ error: "Directory sync config not found" }, { status: 404 });
  }

  await db.directorySyncConfig.delete({ where: { id } });
  return NextResponse.json({}, { status: 204 });
}
