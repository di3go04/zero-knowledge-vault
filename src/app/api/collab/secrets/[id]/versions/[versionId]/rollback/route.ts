import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string; versionId: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id, versionId } = await params;

  const secret = await db.secret.findUnique({ where: { id } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId !== auth.userId) return NextResponse.json({ error: "Solo el owner puede hacer rollback" }, { status: 403 });

  const version = await db.secretVersion.findUnique({ where: { id: versionId } });
  if (!version || version.secretId !== id) return NextResponse.json({ error: "Versión no encontrada" }, { status: 404 });

  await db.secret.update({
    where: { id },
    data: {
      encryptedData: version.encryptedData,
      dataIv: version.dataIv,
      encryptedTitle: version.encryptedTitle ?? undefined,
      titleIv: version.titleIv ?? undefined,
    },
  });

  const nextVersion = await db.secretVersion.findFirst({
    where: { secretId: id },
    orderBy: { versionNumber: "desc" },
    select: { versionNumber: true },
  });

  await db.secretVersion.create({
    data: {
      secretId: id,
      versionNumber: (nextVersion?.versionNumber ?? 0) + 1,
      encryptedData: version.encryptedData,
      dataIv: version.dataIv,
      encryptedTitle: version.encryptedTitle,
      titleIv: version.titleIv,
      createdBy: auth.userId,
      changelog: `Rollback a versión ${version.versionNumber}`,
    },
  });

  return NextResponse.json({
    rolledBack: true,
    versionNumber: version.versionNumber,
    currentEncryptedData: version.encryptedData,
  });
}
