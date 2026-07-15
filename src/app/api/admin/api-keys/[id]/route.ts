import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { apiKeyUpdateSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const apiKey = await db.apiKey.findUnique({
    where: { id },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      permissions: true,
      createdById: true,
      lastUsedAt: true,
      expiresAt: true,
      enabled: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  if (!apiKey) {
    return NextResponse.json({ error: "API key not found" }, { status: 404 });
  }

  return NextResponse.json(apiKey);
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

  const validation = validatePayload(apiKeyUpdateSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const existing = await db.apiKey.findUnique({ where: { id } });
  if (!existing) {
    return NextResponse.json({ error: "API key not found" }, { status: 404 });
  }

  const data: Record<string, unknown> = {};
  if (validation.data.name !== undefined) data.name = validation.data.name;
  if (validation.data.permissions !== undefined) data.permissions = JSON.stringify(validation.data.permissions);
  if (validation.data.enabled !== undefined) data.enabled = validation.data.enabled;
  if (validation.data.expiresAt !== undefined) data.expiresAt = new Date(validation.data.expiresAt);

  const apiKey = await db.apiKey.update({ where: { id }, data });

  return NextResponse.json(apiKey);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const { id } = await params;
  const apiKey = await db.apiKey.findUnique({ where: { id } });
  if (!apiKey) {
    return NextResponse.json({ error: "API key not found" }, { status: 404 });
  }

  await db.apiKey.delete({ where: { id } });
  return NextResponse.json({}, { status: 204 });
}
