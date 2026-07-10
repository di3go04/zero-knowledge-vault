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
import { validateBase64Blob } from "@/lib/crypto-server";
import { randomBytes } from "node:crypto";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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

  const { email, deviceName, publicKeyECDH, publicKeyECDHFingerprint } = body ?? {};

  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "email inválido" }, { status: 400 });
  }
  const normalizedEmail = email.toLowerCase().trim();

  if (
    typeof deviceName !== "string" ||
    deviceName.length === 0 ||
    deviceName.length > DEVICE_NAME_MAX
  ) {
    return NextResponse.json({ error: "deviceName inválido" }, { status: 400 });
  }

  if (
    !publicKeyECDH ||
    typeof publicKeyECDH !== "object" ||
    publicKeyECDH.kty !== "EC" ||
    typeof publicKeyECDH.crv !== "string" ||
    typeof publicKeyECDH.x !== "string" ||
    typeof publicKeyECDH.y !== "string"
  ) {
    return NextResponse.json(
      { error: "publicKeyECDH debe ser JWK EC P-256" },
      { status: 400 },
    );
  }

  if (typeof publicKeyECDHFingerprint !== "string" || !/^[0-9a-f]{64}$/.test(publicKeyECDHFingerprint)) {
    return NextResponse.json(
      { error: "publicKeyECDHFingerprint debe ser hex SHA-256 (64 chars)" },
      { status: 400 },
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
