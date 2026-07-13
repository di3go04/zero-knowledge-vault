/**
 * POST /api/team-vaults/[id]/members — Añade un miembro a la bóveda de equipo.
 *
 *
 * El owner envía la wrappedVaultKey (AES key del vault envuelta con la
 * publicKey RSA del nuevo miembro). El servidor solo almacena el blob.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { pathIdSchema, validatePayload } from "@/lib/validation-schemas";
import { MAX_BLOB_BYTES, validateBase64Blob } from "@/lib/crypto-server";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> },
) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { id } = await params;
  const idValidation = validatePayload(pathIdSchema, id);
  if (!idValidation.success) {
    return NextResponse.json({ error: idValidation.error }, { status: 400 });
  }
  const vaultId = idValidation.data;

  // Verificar que el solicitante es admin del vault
  const vault = await db.teamVault.findUnique({ where: { id: vaultId } });
  if (!vault) {
    return NextResponse.json({ error: "Bóveda no encontrada" }, { status: 404 });
  }

  const membership = await db.teamVaultMember.findUnique({
    where: { teamVaultId_userId: { teamVaultId: vaultId, userId } },
  });
  if (!membership || (membership.role !== "admin" && vault.ownerId !== userId)) {
    return NextResponse.json({ error: "Solo admins pueden añadir miembros" }, { status: 403 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { recipientId, wrappedVaultKey, role } = body ?? {};

  if (typeof recipientId !== "string" || !recipientId) {
    return NextResponse.json({ error: "recipientId requerido" }, { status: 400 });
  }
  if (!validateBase64Blob(wrappedVaultKey, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json({ error: "wrappedVaultKey debe ser base64" }, { status: 400 });
  }
  if (role !== "admin" && role !== "member") {
    return NextResponse.json({ error: "role debe ser 'admin' o 'member'" }, { status: 400 });
  }

  // Verificar que el destinatario existe
  const recipient = await db.user.findUnique({ where: { id: recipientId } });
  if (!recipient) {
    return NextResponse.json({ error: "Destinatario no encontrado" }, { status: 404 });
  }

  const member = await db.teamVaultMember.upsert({
    where: { teamVaultId_userId: { teamVaultId: vaultId, userId: recipientId } },
    update: { wrappedVaultKey, role },
    create: { teamVaultId: vaultId, userId: recipientId, wrappedVaultKey, role },
  });

  return NextResponse.json({
    memberId: member.id,
    vaultId,
    recipientId,
    role: member.role,
    createdAt: member.createdAt,
  });
}
