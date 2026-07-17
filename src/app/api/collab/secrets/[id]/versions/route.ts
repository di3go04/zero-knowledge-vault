import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { createVersionSchema, validatePayload } from "@/lib/validation-schemas";

export async function GET(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;

  const secret = await db.secret.findUnique({ where: { id } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });

  const hasAccess = await db.secretKeyShare.findFirst({
    where: { secretId: id, recipientId: auth.userId },
  });
  if (secret.ownerId !== auth.userId && !hasAccess) {
    return NextResponse.json({ error: "No tienes acceso a este secreto" }, { status: 403 });
  }

  const versions = await db.secretVersion.findMany({
    where: { secretId: id },
    orderBy: { versionNumber: "desc" },
    select: { id: true, versionNumber: true, changelog: true, createdAt: true, createdBy: true },
  });

  return NextResponse.json({ versions });
}

export async function POST(req: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const { id } = await params;

  const secret = await db.secret.findUnique({ where: { id } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId !== auth.userId) return NextResponse.json({ error: "Solo el owner puede crear versiones" }, { status: 403 });

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(createVersionSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { encryptedData, dataIv, encryptedTitle, titleIv, encryptedDiff, diffIv, changelog } = validation.data;

  const lastVersion = await db.secretVersion.findFirst({
    where: { secretId: id },
    orderBy: { versionNumber: "desc" },
    select: { versionNumber: true },
  });

  const versionNumber = (lastVersion?.versionNumber ?? 0) + 1;

  const version = await db.secretVersion.create({
    data: {
      secretId: id,
      versionNumber,
      encryptedData,
      dataIv,
      encryptedTitle,
      titleIv,
      encryptedDiff,
      diffIv,
      createdBy: auth.userId,
      changelog,
    },
  });

  await db.secret.update({
    where: { id },
    data: { encryptedData, dataIv, encryptedTitle: encryptedTitle ?? undefined, titleIv: titleIv ?? undefined },
  });

  return NextResponse.json({
    id: version.id,
    versionNumber: version.versionNumber,
    changelog: version.changelog,
    createdAt: version.createdAt,
  }, { status: 201 });
}
