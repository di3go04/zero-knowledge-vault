import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { directoryConnectorUpdateSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const connector = await db.directoryConnector.findUnique({ where: { id } });
  if (!connector) {
    return NextResponse.json({ error: "Directory connector not found" }, { status: 404 });
  }

  return NextResponse.json(connector);
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

  const validation = validatePayload(directoryConnectorUpdateSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.directoryConnector.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Directory connector not found" }, { status: 404 });
  }

  const connector = await db.directoryConnector.update({
    where: { id },
    data: validation.data,
  });

  return NextResponse.json(connector);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const connector = await db.directoryConnector.findUnique({ where: { id } });
  if (!connector) {
    return NextResponse.json({ error: "Directory connector not found" }, { status: 404 });
  }

  await db.directoryConnector.delete({ where: { id } });
  return NextResponse.json({}, { status: 204 });
}
