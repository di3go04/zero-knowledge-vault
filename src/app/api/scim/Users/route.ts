import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { z } from "zod";

const scimAuth = (req: NextRequest): boolean => {
  const auth = req.headers.get("authorization");
  if (!auth?.startsWith("Bearer ")) return false;
  return auth.slice(7) === process.env.SCIM_API_TOKEN;
};

const createUserSchema = z.object({
  schemas: z.array(z.string()),
  userName: z.string().email(),
  displayName: z.string().optional(),
  active: z.boolean().default(true),
});

export async function GET(req: NextRequest) {
  if (!scimAuth(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const users = await db.user.findMany({ select: { id: true, email: true, name: true } });
  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: users.length,
    Resources: users.map(u => ({
      id: u.id,
      userName: u.email,
      displayName: u.name || u.email,
      active: true,
    })),
  });
}

export async function POST(req: NextRequest) {
  if (!scimAuth(req)) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json();
  const validation = createUserSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json({ detail: validation.error.issues[0].message }, { status: 400 });
  }

  const { userName, displayName } = validation.data;
  const existing = await db.user.findUnique({ where: { email: userName.toLowerCase() } });
  if (existing) {
    return NextResponse.json({ detail: "User already exists" }, { status: 409 });
  }

  const user = await db.user.create({
    data: { email: userName.toLowerCase(), name: displayName || null },
  });

  return NextResponse.json({
    id: user.id,
    userName: user.email,
    displayName: user.name,
    active: true,
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
  }, { status: 201 });
}
