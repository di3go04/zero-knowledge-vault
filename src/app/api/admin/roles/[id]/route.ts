import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { roleUpdateSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const role = await db.role.findUnique({
    where: { id },
    include: {
      permissions: true,
      _count: { select: { userRoles: true } },
    },
  });
  if (!role) {
    return NextResponse.json({ error: "Role not found" }, { status: 404 });
  }

  return NextResponse.json(role);
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

  const validation = validatePayload(roleUpdateSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.role.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "Role not found" }, { status: 404 });
  }
  if (existing.isSystem) {
    return NextResponse.json({ error: "Cannot modify system role" }, { status: 403 });
  }

  const role = await db.role.update({ where: { id }, data: validation.data });

  return NextResponse.json(role);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const role = await db.role.findUnique({ where: { id } });
  if (!role) {
    return NextResponse.json({ error: "Role not found" }, { status: 404 });
  }
  if (role.isSystem) {
    return NextResponse.json({ error: "Cannot delete system role" }, { status: 403 });
  }

  await db.role.delete({ where: { id } });
  return NextResponse.json({}, { status: 204 });
}
