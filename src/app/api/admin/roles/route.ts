import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { db } from "@/lib/db";
import { z } from "zod";

const roleSchema = z.object({
  userId: z.string(),
  role: z.enum(["admin", "member", "viewer"]),
});

const userRoles = new Map<string, string>();

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const body = await req.json();
  const validation = roleSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error.issues[0].message }, { status: 400 });
  }

  const { userId, role } = validation.data;
  userRoles.set(userId, role);
  return NextResponse.json({ userId, role });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const roles = Array.from(userRoles.entries()).map(([userId, role]) => ({ userId, role }));
  return NextResponse.json({ roles });
}
