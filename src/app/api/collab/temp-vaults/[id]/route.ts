import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { updateTempVaultSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;
  const { id } = await params;

  const vault = await db.tempVault.findUnique({ where: { id } });
  if (!vault) return NextResponse.json({ error: "Vault no encontrado" }, { status: 404 });
  if (vault.ownerId !== userId) return NextResponse.json({ error: "No autorizado" }, { status: 403 });

  return NextResponse.json(vault);
}

export async function PATCH(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;
  const { id } = await params;

  const vault = await db.tempVault.findUnique({ where: { id } });
  if (!vault) return NextResponse.json({ error: "Vault no encontrado" }, { status: 404 });
  if (vault.ownerId !== userId) return NextResponse.json({ error: "No autorizado" }, { status: 403 });

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(updateTempVaultSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { name, encryptedData, dataIv, expiresInHours } = validation.data;
  const updateData: Record<string, unknown> = {};
  if (name !== undefined) updateData.name = name;
  if (encryptedData !== undefined) updateData.encryptedData = encryptedData;
  if (dataIv !== undefined) updateData.dataIv = dataIv;
  if (expiresInHours !== undefined) updateData.expiresAt = new Date(Date.now() + expiresInHours * 3600_000);

  const updated = await db.tempVault.update({ where: { id }, data: updateData });
  return NextResponse.json(updated);
}

export async function DELETE(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;
  const { id } = await params;

  const vault = await db.tempVault.findUnique({ where: { id } });
  if (!vault) return NextResponse.json({ error: "Vault no encontrado" }, { status: 404 });
  if (vault.ownerId !== userId) return NextResponse.json({ error: "No autorizado" }, { status: 403 });

  await db.tempVault.delete({ where: { id } });
  return NextResponse.json({ deleted: true });
}
