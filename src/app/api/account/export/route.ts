/**
 * GET /api/account/export — Exportación de datos personales (GDPR Art. 20).
 *
 *
 * Los datos se devuelen tal como están en la BD (cifrados). El cliente
 * puede descifrarlos localmente con su masterKey si lo desea.
 */
import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/auth-helper";
import { exportUserData } from "@/lib/gdpr-export";

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const data = await exportUserData(userId);

  return NextResponse.json(data, {
    headers: {
      "Content-Disposition": `attachment; filename="zk-vault-export-${Date.now()}.json"`,
    },
  });
}
