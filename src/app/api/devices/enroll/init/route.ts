/**
 * POST /api/devices/enroll/init
 *
 * Dispositivo NUEVO (B) llama a este endpoint para iniciar el enrollment.
 * No requiere autenticación (no tiene sesión todavía).
 *
 * Body:
 *   { email, deviceName, publicKeyECDH (JWK), publicKeyECDHFingerprint (hex) }
 *
 * El servidor:
 *   1. Verifica que el email existe (si no, devuelve 404 — anti-enumeración
 *      no aplica aquí porque el dispositivo nuevo DEBE saber el email).
 *   2. Crea un Device con enrollCode de 6 dígitos, expira en 5 min.
 *   3. Devuelve { enrollCode, deviceId } al dispositivo B.
 *
 * El dispositivo B muestra el enrollCode al usuario, quien lo introduce
 * en el dispositivo A (ya autenticado) para completar el enrollment.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { randomBytes } from "node:crypto";
import { enrollInitSchema, validatePayload } from "@/lib/validation-schemas";
import { checkRateLimit, getClientIp, RATE_LIMIT_POLICIES } from "@/lib/rate-limit";

const ENROLL_CODE_TTL_MS = 5 * 60 * 1000; // 5 minutos
const DEVICE_NAME_MAX = 80;

function generateServerEnrollCode(): string {
  const bytes = randomBytes(4);
  const num = ((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0;
  return (num % 1_000_000).toString().padStart(6, "0");
}

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  // Validar con Zod primero
  const validation = validatePayload(enrollInitSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { email, deviceName, publicKeyECDH, publicKeyECDHFingerprint } = validation.data;
  const normalizedEmail = email.toLowerCase().trim();

  // -------- Rate limit anti-spam de dispositivos --------
  // 3 intentos / 5 min / IP+email. Previene que un atacante cree
  // miles de dispositivos pendientes para saturar la BD.
  const ip = getClientIp(req);
  const rlKey = `enroll-init:${ip}:${normalizedEmail}`;
  const rl = await checkRateLimit(
    rlKey,
    RATE_LIMIT_POLICIES.enrollInit.maxAttempts,
    RATE_LIMIT_POLICIES.enrollInit.windowMs,
  );
  if (!rl.allowed) {
    return NextResponse.json(
      {
        error: "Demasiados intentos de enrollment. Espera antes de reintentar.",
        retryAfter: rl.retryAfterSeconds,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(rl.retryAfterSeconds),
          "X-RateLimit-Remaining": "0",
        },
      },
    );
  }

  // Verificar que el usuario existe
  const user = await db.user.findUnique({ where: { email: normalizedEmail } });
  if (!user) {
    return NextResponse.json({ error: "Usuario no encontrado" }, { status: 404 });
  }

  // Generar código de enrollment
  const enrollCode = generateServerEnrollCode();
  const enrollCodeExpiresAt = new Date(Date.now() + ENROLL_CODE_TTL_MS);

  // Crear Device (sin wrappedPrivateKey todavía — se completa en /enroll/complete)
  const device = await db.device.create({
    data: {
      userId: user.id,
      deviceName: deviceName.slice(0, DEVICE_NAME_MAX),
      publicKeyECDH: JSON.stringify(publicKeyECDH),
      publicKeyECDHFingerprint,
      // Placeholder — el dispositivo A lo reemplazará en /enroll/complete
      wrappedPrivateKeyForDevice: "",
      wrappedPrivateKeyIv: "",
      enrollCode,
      enrollCodeExpiresAt,
    },
  });

  return NextResponse.json({
    deviceId: device.id,
    enrollCode,
    expiresAt: enrollCodeExpiresAt.toISOString(),
    note: "Muestra este código al usuario. Debe introducirlo en un dispositivo ya autenticado para completar el enrollment.",
  });
}
