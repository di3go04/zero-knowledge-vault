import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { permissionSchema, validatePayload } from "@/lib/validation-schemas";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const role = await db.role.findUnique({ where: { id } });
  if (!role) {
    return NextResponse.json({ error: "Role not found" }, { status: 404 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(permissionSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const permission = await db.permission.create({
    data: { roleId: id, ...validation.data },
  });

  return NextResponse.json(permission, { status: 201 });
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;

  const searchParams = req.nextUrl.searchParams;
  const permissionId = searchParams.get("permissionId");
  if (!permissionId) {
    return NextResponse.json({ error: "permissionId query param required" }, { status: 400 });
  }

  const permission = await db.permission.findUnique({ where: { id: permissionId } });
  if (!permission || permission.roleId !== id) {
    return NextResponse.json({ error: "Permission not found for this role" }, { status: 404 });
  }

  await db.permission.delete({ where: { id: permissionId } });
  return NextResponse.json({}, { status: 204 });
}
