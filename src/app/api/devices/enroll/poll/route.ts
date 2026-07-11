/**
 * POST /api/devices/enroll/poll
 *
 * MEJORA Fase 3 — Challenge-Response ECDH:
 *
 * El Dispositivo B llama a este endpoint para:
 *   - Saber si el enrollment fue completado (status check)
 *   - Obtener un challenge criptográfico (nonce 32 bytes) que debe firmar
 *     con su privateKey ECDH para recibir la wrappedPrivateKeyForDevice
 *
 * El challenge se almacena en memoria (Map server-side) con TTL de 60s
 * asociado al deviceId. Un challenge solo se puede usar una vez.
 *
 * Flujo completo:
 *   1. B llama a poll → recibe { enrolled: true, challenge }
 *   2. B firma challenge con su privateKey ECDH (ECDSA P-256)
 *   3. B llama a poll/verify con { deviceId, challenge, signature }
 *   4. Servidor verifica firma contra publicKeyECDH registrada
 *   5. Si válida → devuelve wrappedPrivateKeyForDevice
 *
 * Esto cierra la brecha de suplantación: un atacante con el deviceId
 * no puede responder al challenge sin la privateKey ECDH.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { randomBytes } from "node:crypto";
import { enrollPollSchema, validatePayload } from "@/lib/validation-schemas";
import { saveChallenge } from "@/lib/challenge-store";

const CHALLENGE_TTL_MS = 60_000; // 60 segundos

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(enrollPollSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { deviceId } = validation.data;

  const device = await db.device.findUnique({ where: { id: deviceId } });
  if (!device) {
    return NextResponse.json({ error: "Dispositivo no encontrado" }, { status: 404 });
  }

  if (device.revokedAt) {
    return NextResponse.json({ error: "Dispositivo revocado" }, { status: 403 });
  }

  // Verificar que el enrollment fue completado
  if (!device.wrappedPrivateKeyForDevice || device.wrappedPrivateKeyIv === "") {
    return NextResponse.json({
      enrolled: false,
      message: "El enrollment aún no ha sido completado. Espera a que el dispositivo autorizado introduzca el código.",
    });
  }

  // Generar challenge criptográfico (32 bytes aleatorios)
  const challengeBytes = randomBytes(32);
  const challenge = challengeBytes.toString("base64");

  // Almacenar challenge en Redis (o Map fallback) con TTL de 60s
  await saveChallenge(deviceId, challenge, CHALLENGE_TTL_MS);

  await db.device.update({
    where: { id: deviceId },
    data: { lastSeenAt: new Date() },
  });

  return NextResponse.json({
    enrolled: true,
    deviceId: device.id,
    deviceName: device.deviceName,
    challenge,
    challengeExpiresIn: CHALLENGE_TTL_MS / 1000,
    publicKeyECDHFingerprint: device.publicKeyECDHFingerprint,
    nextStep: "Firma el challenge con tu privateKey ECDH (ECDSA P-256) y llama a POST /api/devices/enroll/poll/verify con { deviceId, challenge, signature }.",
  });
}
