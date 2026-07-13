/**
 * /api/team-vaults
 *   GET — Lista bóvedas de equipo del usuario.
 *   POST — Crea una nueva bóveda de equipo.
 *
 *
 * La bóveda tiene su propia llave AES, cifrada con la publicKey del owner.
 * Los miembros reciben la llave AES envuelta con su publicKey.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import {
  IV_EXPECTED_BYTES,
  MAX_BLOB_BYTES,
  validateBase64Blob,
} from "@/lib/crypto-server";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const vaults = await db.teamVault.findMany({
    where: {
      OR: [
        { ownerId: userId },
        { members: { some: { userId } } },
      ],
    },
    include: {
      members: {
        include: {
          user: { select: { email: true, name: true } },
        },
      },
    },
  });

  return NextResponse.json({
    vaults: vaults.map((v) => ({
      id: v.id,
      name: v.name,
      ownerId: v.ownerId,
      isOwner: v.ownerId === userId,
      memberCount: v.members.length,
      members: v.members.map((m) => ({
        userId: m.userId,
        email: m.user.email,
        name: m.user.name,
        role: m.role,
      })),
      createdAt: v.createdAt,
    })),
  });
}

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { name, encryptedVaultKey, vaultKeyIv } = body ?? {};

  if (typeof name !== "string" || name.length === 0 || name.length > 80) {
    return NextResponse.json({ error: "name debe ser 1-80 caracteres" }, { status: 400 });
  }
  if (!validateBase64Blob(encryptedVaultKey, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json({ error: "encryptedVaultKey debe ser base64" }, { status: 400 });
  }
  if (!validateBase64Blob(vaultKeyIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json({ error: `vaultKeyIv debe ser ${IV_EXPECTED_BYTES} bytes` }, { status: 400 });
  }

  const vault = await db.teamVault.create({
    data: {
      name,
      ownerId: userId,
      encryptedVaultKey,
      vaultKeyIv,
    },
  });

  // El owner es automáticamente miembro admin
  await db.teamVaultMember.create({
    data: {
      teamVaultId: vault.id,
      userId,
      role: "admin",
      wrappedVaultKey: encryptedVaultKey, // misma wrappedKey del owner
    },
  });

  return NextResponse.json({
    vaultId: vault.id,
    name: vault.name,
    createdAt: vault.createdAt,
  });
}
