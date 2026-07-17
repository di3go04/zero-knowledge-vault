import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { importPasswordsSchema, validatePayload, parsePagination } from "@/lib/validation-schemas";
import { logImportExport } from "@/lib/collab/import-export";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(importPasswordsSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { source, items } = validation.data;

  try {
    const results = await db.$transaction(async (tx) => {
      const created: Array<{ id: string; encryptedTitle: string }> = [];
      for (const item of items) {
        const secret = await tx.secret.create({
          data: {
            ownerId: userId,
            encryptedTitle: item.encryptedTitle,
            titleIv: item.titleIv,
            encryptedData: item.encryptedData,
            dataIv: item.dataIv,
            secretType: item.secretType,
            encryptedMetadata: item.encryptedMetadata ?? null,
            metadataIv: item.metadataIv ?? null,
          },
        });
        await tx.secretKeyShare.create({
          data: {
            secretId: secret.id,
            recipientId: userId,
            wrappedSymmetricKey: "",
          },
        });
        created.push({ id: secret.id, encryptedTitle: secret.encryptedTitle });
      }
      return created;
    });

    await logImportExport(userId, "import", source, results.length, "completed");

    return NextResponse.json({ imported: results.length, secrets: results }, { status: 201 });
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : "Error desconocido";
    await logImportExport(userId, "import", source, 0, "failed", errorMsg);
    return NextResponse.json({ error: "Error al importar", details: errorMsg }, { status: 500 });
  }
}

export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const { offset, limit } = parsePagination(req.nextUrl.searchParams);

  const [logs, total] = await Promise.all([
    db.importExportLog.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
      skip: offset,
      take: limit,
    }),
    db.importExportLog.count({ where: { userId } }),
  ]);

  return NextResponse.json({ logs, pagination: { offset, limit, total, hasMore: offset + limit < total } });
}
