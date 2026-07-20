/**
 * POST /api/auth/recovery/setup
 *
 * BLOQUE 2 — Configura el backup de recuperación BIP-39 para el usuario.
 *
 * El cliente envía:
 *   - recoverySalt (base64, 16-64 bytes)
 *   - recoveryIterations (310k-1M)
 *   - encryptedPrivateKeyForRecovery (base64, AES-256-GCM)
 *   - recoveryIv (base64, 12 bytes)
 *
 * El servidor:
 *   1. Verifica autenticación (Bearer token).
 *   2. Aplica rate-limit estricto: 5 setup intentos / 1 hora / usuario.
 *      Esto mitiga ataques de fuerza bruta sobre el mnemonic BIP-39.
 *   3. Valida los blobs con Zod.
 *   4. Actualiza UserKeyMaterial con los campos recovery*.
 *
 * El servidor nunca ve el mnemonic BIP-39 — solo el blob cifrado.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { requireAuth } from "@/lib/auth-helper";
import { checkRateLimit, rateLimitResponse, getClientIp } from "@/lib/rate-limit";
import { z } from "zod";
import { logger } from "@/lib/logger";

const recoverySetupSchema = z.object({
  recoverySalt: z.string().min(1),
  recoveryIterations: z.number().int().min(310_000).max(1_000_000),
  encryptedPrivateKeyForRecovery: z.string().min(1),
  recoveryIv: z.string().min(1),
});

export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  // BLOQUE 2 — Rate-limit estricto: 5 setup intentos / 1 hora / usuario+IP.
  // Mitiga fuerza bruta sobre el mnemonic BIP-39 (aunque el brute-force
  // real ocurre offline si el atacante tiene el blob cifrado, este
  // rate-limit protege el endpoint online).
  const ip = getClientIp(req);
  const rlKey = `recovery:setup:${userId}:${ip}`;
  const rl = await checkRateLimit(rlKey, 5, 60 * 60 * 1000);
  if (!rl.allowed) {
    logger.warn({ userId, ip }, "recovery setup rate limited");
    return rateLimitResponse(rl.retryAfterSeconds, rl.remaining);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = recoverySetupSchema.safeParse(body);
  if (!validation.success) {
    return NextResponse.json(
      { error: validation.error.issues[0]?.message ?? "Validación fallida" },
      { status: 400 },
    );
  }

  const {
    recoverySalt,
    recoveryIterations,
    encryptedPrivateKeyForRecovery,
    recoveryIv,
  } = validation.data;

  try {
    await db.userKeyMaterial.update({
      where: { userId },
      data: {
        recoverySalt,
        recoveryIterations,
        encryptedPrivateKeyForRecovery,
        recoveryIv,
        recoveryEnabled: true,
      },
    });

    logger.info({ userId }, "recovery setup completed");
    return NextResponse.json({
      ok: true,
      recoveryEnabled: true,
      note: "Backup de recuperación configurado. Guarda tu frase BIP-39 en un lugar seguro — sin ella, tu cuenta es irrecuperable.",
    });
  } catch (err) {
    logger.error({ userId, err: String(err) }, "recovery setup failed");
    return NextResponse.json(
      { error: "Error al configurar recovery" },
      { status: 500 },
    );
  }
}
