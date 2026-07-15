import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { scimUserSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const scimUser = await db.scimUser.findUnique({
    where: { externalId: id },
    include: { user: { select: { id: true, email: true, name: true } } },
  });
  if (!scimUser) {
    return NextResponse.json({ error: "SCIM user not found" }, { status: 404 });
  }

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: scimUser.externalId,
    externalId: scimUser.externalId,
    userName: scimUser.userName,
    name: { givenName: scimUser.user.name ?? undefined },
    emails: [{ value: scimUser.user.email, primary: true }],
    active: scimUser.active,
    meta: { resourceType: "User", created: scimUser.createdAt, lastModified: scimUser.updatedAt },
  });
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

  const validation = validatePayload(scimUserSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const scimUser = await db.scimUser.findUnique({ where: { externalId: id } });
  if (!scimUser) {
    return NextResponse.json({ error: "SCIM user not found" }, { status: 404 });
  }

  const updated = await db.scimUser.update({
    where: { externalId: id },
    data: {
      userName: body.userName,
      active: body.active ?? scimUser.active,
    },
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: updated.externalId,
    externalId: updated.externalId,
    userName: updated.userName,
    name: { givenName: updated.user.name ?? undefined },
    emails: [{ value: updated.user.email, primary: true }],
    active: updated.active,
    meta: { resourceType: "User", created: updated.createdAt, lastModified: updated.updatedAt },
  });
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const scimUser = await db.scimUser.findUnique({ where: { externalId: id } });
  if (!scimUser) {
    return NextResponse.json({ error: "SCIM user not found" }, { status: 404 });
  }

  const data: any = {};
  if (body.active !== undefined) data.active = body.active;
  if (body.userName) data.userName = body.userName;

  const updated = await db.scimUser.update({
    where: { externalId: id },
    data,
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  return NextResponse.json({
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: updated.externalId,
    externalId: updated.externalId,
    userName: updated.userName,
    name: { givenName: updated.user.name ?? undefined },
    emails: [{ value: updated.user.email, primary: true }],
    active: updated.active,
    meta: { resourceType: "User", created: updated.createdAt, lastModified: updated.updatedAt },
  });
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const scimUser = await db.scimUser.findUnique({ where: { externalId: id } });
  if (!scimUser) {
    return NextResponse.json({ error: "SCIM user not found" }, { status: 404 });
  }

  await db.scimUser.delete({ where: { externalId: id } });
  return NextResponse.json({}, { status: 204 });
}
