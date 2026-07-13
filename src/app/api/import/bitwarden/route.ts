/**
 * POST /api/import/bitwarden — Importa secretos desde export JSON de Bitwarden.
 *
 *
 * El cliente envía un array de secretos ya cifrados (como si los hubiera
 * creado manualmente). El servidor solo valida y almacena los blobs.
 *
 * El cliente debe:
 *   1. Parsear el JSON de Bitwarden
 *   2. Para cada item, cifrar título + contenido con AES-256-GCM
 *   3. Generar wrappedKey para cada uno
 *   4. Enviar el array de blobs cifrados a este endpoint
 *
 * El servidor NO ve el contenido del export de Bitwarden.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { z } from "zod";

const importItemSchema = z.object({
  encryptedTitle: z.string().min(1),
  titleIv: z.string().min(1),
  encryptedData: z.string().min(1),
  dataIv: z.string().min(1),
  wrappedKeyForOwner: z.string().length(380), // RSA-2048 base64 ≈ 380 chars
});

const importSchema = z.object({
  items: z.array(importItemSchema).min(1).max(500),
});

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

  const validation = importSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json(
      { error: validation.error.issues.map((i) => i.message).join("; ") },
      { status: 400 },
    );
  }

  const { items } = validation.data;

  // Crear todos los secretos en una transacción
  const result = await db.$transaction(
    items.map((item) =>
      db.secret.create({
        data: {
          ownerId: userId,
          encryptedTitle: item.encryptedTitle,
          titleIv: item.titleIv,
          encryptedData: item.encryptedData,
          dataIv: item.dataIv,
          keyShares: {
            create: {
              recipientId: userId,
              wrappedSymmetricKey: item.wrappedKeyForOwner,
            },
          },
        },
      }),
    ),
  );

  return NextResponse.json({
    imported: result.length,
    secretIds: result.map((s) => s.id),
  });
}
