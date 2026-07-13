/**
 * DELETE /api/account/delete — Crypto-shredding + eliminación completa.
 *
 *
 * Ejecuta cryptoShredUser() que:
 *   1. Sobrescribe blobs cifrados con basura
 *   2. Elimina todos los secrets, shares, devices, logs, comments
 *   3. Elimina UserKeyMaterial
 *   4. Elimina User
 *
 * Tras esto, los datos son criptográficamente irrecuperables.
 */
import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { cryptoShredUser } from "@/lib/crypto-shredding";

export async function DELETE(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const result = await cryptoShredUser(userId);

  return NextResponse.json({
    deleted: true,
    userId,
    details: result.details,
    note: "Cuenta eliminada con crypto-shredding. Los datos son criptográficamente irrecuperables.",
  });
}
