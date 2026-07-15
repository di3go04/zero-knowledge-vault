import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { scimUserSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const filter = req.nextUrl.searchParams.get("filter");
  const startIndex = Math.max(1, parseInt(req.nextUrl.searchParams.get("startIndex") ?? "1", 10));
  const count = Math.min(100, Math.max(1, parseInt(req.nextUrl.searchParams.get("count") ?? "50", 10)));

  const where: any = {};
  if (filter) {
    const match = filter.match(/^userName\s+eq\s+"([^"]+)"$/);
    if (match) where.userName = match[1];
  }

  const [scimUsers, total] = await Promise.all([
    db.scimUser.findMany({
      where,
      include: { user: { select: { id: true, email: true, name: true } } },
      skip: startIndex - 1,
      take: count,
      orderBy: { createdAt: "desc" },
    }),
    db.scimUser.count({ where }),
  ]);

  const Resources = scimUsers.map((su) => ({
    id: su.externalId,
    externalId: su.externalId,
    userName: su.userName,
    name: { givenName: su.user.name ?? undefined },
    emails: [{ value: su.user.email, primary: true }],
    active: su.active,
    meta: { resourceType: "User", created: su.createdAt, lastModified: su.updatedAt },
  }));

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: total,
    startIndex,
    itemsPerPage: count,
    Resources,
  });
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

  const validation = validatePayload(scimUserSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const userEmail = body.emails?.[0]?.value;
  if (!userEmail) {
    return NextResponse.json({ error: "emails[0].value is required" }, { status: 400 });
  }

  const user = await db.user.findUnique({ where: { email: userEmail.toLowerCase().trim() } });
  if (!user) {
    return NextResponse.json({ error: "User not found" }, { status: 404 });
  }

  const existing = await db.scimUser.findUnique({ where: { userId: user.id } });
  if (existing) {
    return NextResponse.json({ error: "User already has a SCIM profile" }, { status: 409 });
  }

  const externalId = body.externalId ?? `scim-${user.id}`;
  const scimUser = await db.scimUser.create({
    data: {
      userId: user.id,
      externalId,
      userName: body.userName,
      active: body.active ?? true,
    },
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: scimUser.externalId,
    externalId: scimUser.externalId,
    userName: scimUser.userName,
    name: { givenName: scimUser.user.name ?? undefined },
    emails: [{ value: scimUser.user.email, primary: true }],
    active: scimUser.active,
    meta: { resourceType: "User", created: scimUser.createdAt, lastModified: scimUser.updatedAt },
  }, { status: 201 });
}
