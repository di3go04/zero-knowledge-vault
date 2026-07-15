import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { rolePermissionOverrideSchema, validatePayload } from "@/lib/validation-schemas";

export async function PUT(req: NextRequest, { params }: { params: Promise<{ id: string; permId: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id, permId } = await params;
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(rolePermissionOverrideSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.rolePermissionOverride.findFirst({ where: { id: permId, roleId: id } });
  if (!existing) {
    return NextResponse.json({ error: "Permission override not found" }, { status: 404 });
  }

  const override = await db.rolePermissionOverride.update({
    where: { id: permId },
    data: validation.data,
  });

  return NextResponse.json(override);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string; permId: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id, permId } = await params;
  const existing = await db.rolePermissionOverride.findFirst({ where: { id: permId, roleId: id } });
  if (!existing) {
    return NextResponse.json({ error: "Permission override not found" }, { status: 404 });
  }

  await db.rolePermissionOverride.delete({ where: { id: permId } });
  return NextResponse.json({}, { status: 204 });
}
