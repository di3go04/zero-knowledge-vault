import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { apiKeySchema, validatePayload } from "@/lib/validation-schemas";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;

  const keys = await db.apiKey.findMany({
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
    orderBy: { createdAt: "desc" },
  });

  return NextResponse.json({ apiKeys: keys });
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

  const validation = validatePayload(apiKeySchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const rawKey = `zkv_${crypto.randomBytes(32).toString("hex")}`;
  const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
  const keyPrefix = rawKey.substring(0, 8);

  const apiKey = await db.apiKey.create({
    data: {
      name: validation.data.name,
      keyPrefix,
      keyHash,
      permissions: JSON.stringify(validation.data.permissions),
      createdById: auth.userId,
      expiresAt: validation.data.expiresAt ? new Date(validation.data.expiresAt) : null,
    },
  });

  return NextResponse.json(
    {
      id: apiKey.id,
      name: apiKey.name,
      keyPrefix: apiKey.keyPrefix,
      permissions: apiKey.permissions,
      createdAt: apiKey.createdAt,
      rawKey,
    },
    { status: 201 },
  );
}
