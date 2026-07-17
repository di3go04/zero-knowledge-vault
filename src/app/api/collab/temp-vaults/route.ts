import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { createTempVaultSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(createTempVaultSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { name, encryptedData, dataIv, expiresInHours } = validation.data;
  const expiresAt = new Date(Date.now() + expiresInHours * 3600_000);

  const vault = await db.tempVault.create({
    data: { ownerId: userId, name, encryptedData, dataIv, expiresAt },
  });

  return NextResponse.json({
    id: vault.id,
    name: vault.name,
    expiresAt: vault.expiresAt,
    status: vault.status,
    createdAt: vault.createdAt,
  }, { status: 201 });
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const [vaults, total] = await Promise.all([
    db.tempVault.findMany({
      where: { ownerId: userId },
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.tempVault.count({ where: { ownerId: userId } }),
  ]);

  return NextResponse.json({ vaults, pagination: { offset, limit, total, hasMore: offset + limit < total } });
}
