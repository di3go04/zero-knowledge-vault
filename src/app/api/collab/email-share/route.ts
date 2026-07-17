import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { emailShareSchema, validatePayload } from "@/lib/validation-schemas";
import { randomBytes } from "node:crypto";

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const senderId = auth.userId;

  let body: any;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "JSON inválido" }, { status: 400 }); }

  const validation = validatePayload(emailShareSchema, body);
  if (!validation.success) return NextResponse.json({ error: validation.error }, { status: 400 });

  const { secretId, recipientEmail, message, expiresInHours } = validation.data;

  const secret = await db.secret.findUnique({ where: { id: secretId } });
  if (!secret) return NextResponse.json({ error: "Secreto no encontrado" }, { status: 404 });
  if (secret.ownerId !== senderId) return NextResponse.json({ error: "Solo el owner puede compartir" }, { status: 403 });

  const token = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + expiresInHours * 3600_000);

  const emailShare = await db.emailShare.create({
    data: { secretId, senderId, recipientEmail: recipientEmail.toLowerCase().trim(), token, message, expiresAt },
  });

  const magicLink = `${req.nextUrl.origin}/api/collab/email-share/${token}`;

  return NextResponse.json({
    id: emailShare.id,
    recipientEmail: emailShare.recipientEmail,
    magicLink,
    expiresAt: emailShare.expiresAt,
    status: emailShare.status,
  }, { status: 201 });
}
