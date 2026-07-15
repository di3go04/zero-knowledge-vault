import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { roleSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const roles = await db.role.findMany({
    include: {
      permissions: { select: { id: true, action: true, resource: true, conditions: true } },
      _count: { select: { userRoles: true } },
    },
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ roles });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const validation = validatePayload(roleSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const role = await db.role.create({ data: validation.data });

  return NextResponse.json(role, { status: 201 });
}
