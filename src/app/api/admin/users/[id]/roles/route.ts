import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { userRoleAssignmentSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const user = await db.user.findUnique({ where: { id } });
  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  const userRoles = await db.userRole.findMany({
    where: { userId: id },
    include: {
      role: {
        include: { permissions: { select: { id: true, action: true, resource: true } } },
      },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ roles: userRoles.map((ur) => ur.role) });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const user = await db.user.findUnique({ where: { id } });
  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(userRoleAssignmentSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const role = await db.role.findUnique({ where: { id: validation.data.roleId } });
  if (!role) {
    return NextResponse.json({ error: "Role not found" }, { status: 404 });
  }

  const existing = await db.userRole.findUnique({
    where: { userId_roleId: { userId: id, roleId: role.id } },
  });
  if (existing) {
    return NextResponse.json({ error: "User already has this role" }, { status: 409 });
  }

  const userRole = await db.userRole.create({
    data: { userId: id, roleId: role.id, assignedBy: auth.userId },
    include: { role: true },
  });

  return NextResponse.json(userRole, { status: 201 });
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const searchParams = req.nextUrl.searchParams;
  const roleId = searchParams.get("roleId");
  if (!roleId) {
    return NextResponse.json({ error: "roleId query param required" }, { status: 400 });
  }

  const userRole = await db.userRole.findUnique({
    where: { userId_roleId: { userId: id, roleId } },
  });
  if (!userRole) {
    return NextResponse.json({ error: "Role assignment not found" }, { status: 404 });
  }

  await db.userRole.delete({ where: { id: userRole.id } });
  return NextResponse.json({}, { status: 204 });
}
