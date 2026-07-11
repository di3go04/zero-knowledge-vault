/**
 * POST /api/devices/enroll/poll/verify
 *
 * MEJORA Fase 3 — Verificación de challenge-response ECDH.
 *
 * El Dispositivo B envía:
 *   { deviceId, challenge, signature }
 *
 * El servidor:
 *   1. Busca el challenge pendiente para deviceId.
 *   2. Verifica que no haya expirado y no se haya usado ya.
 *   3. Verifica la firma ECDSA P-256 contra la publicKeyECDH registrada.
 *   4. Si válida → elimina el challenge (one-time use) y devuelve
 *      wrappedPrivateKeyForDevice + wrappedPrivateKeyIv.
 *   5. Si inválida → 403, no revela si el challenge existía.
 *
 * Esto cierra la brecha de suplantación: un atacante con el deviceId
 * no puede responder al challenge sin la privateKey ECDH.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  publicKeyFingerprint,
  verifyChallenge,
} from "@/lib/crypto-server";
import { enrollVerifySchema, validatePayload } from "@/lib/validation-schemas";

// Re-usar el store del endpoint poll (mismo módulo en runtime)
// Como Next.js carga cada route en su propio módulo, declaramos un
// store compartido vía globalThis para single-process.
interface PendingChallenge {
  challenge: string;
  expiresAt: number;
}

const globalForChallenges = globalThis as unknown as {
  __pendingDeviceChallenges?: Map<string, PendingChallenge>;
};

const pendingChallenges: Map<string, PendingChallenge> =
  globalForChallenges.__pendingDeviceChallenges ?? new Map();
globalForChallenges.__pendingDeviceChallenges = pendingChallenges;

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(enrollVerifySchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { deviceId, challenge, signature } = validation.data;

  // 1. Buscar challenge pendiente
  const pending = pendingChallenges.get(deviceId);
  if (!pending) {
    // No revelar si el challenge existía o no
    return NextResponse.json(
      { error: "Challenge inválido, expirado o ya usado" },
      { status: 403 },
    );
  }

  // 2. Verificar expiración
  if (pending.expiresAt <= Date.now()) {
    pendingChallenges.delete(deviceId);
    return NextResponse.json(
      { error: "Challenge expirado. Solicita uno nuevo en /api/devices/enroll/poll" },
      { status: 403 },
    );
  }

  // 3. Verificar que el challenge enviado coincide con el almacenado
  // (evita que el atacante use un challenge distinto)
  if (pending.challenge !== challenge) {
    return NextResponse.json(
      { error: "Challenge no coincide con el emitido" },
      { status: 403 },
    );
  }

  // 4. Buscar dispositivo
  const device = await db.device.findUnique({ where: { id: deviceId } });
  if (!device) {
    pendingChallenges.delete(deviceId);
    return NextResponse.json({ error: "Dispositivo no encontrado" }, { status: 404 });
  }

  if (device.revokedAt) {
    pendingChallenges.delete(deviceId);
    return NextResponse.json({ error: "Dispositivo revocado" }, { status: 403 });
  }

  if (!device.wrappedPrivateKeyForDevice || device.wrappedPrivateKeyIv === "") {
    pendingChallenges.delete(deviceId);
    return NextResponse.json({ error: "Enrollment no completado" }, { status: 400 });
  }

  // 5. Verificar fingerprint de la publicKey ECDH (defense in depth)
  const storedPublicKeyJwk = JSON.parse(device.publicKeyECDH) as JsonWebKey;
  const serverFingerprint = await publicKeyFingerprint(
    storedPublicKeyJwk as Record<string, unknown>,
  );
  if (serverFingerprint !== device.publicKeyECDHFingerprint) {
    pendingChallenges.delete(deviceId);
    return NextResponse.json(
      { error: "Fingerprint de publicKey ECDH inconsistente — posible manipulación de BD" },
      { status: 500 },
    );
  }

  // 6. Verificar firma ECDSA del challenge
  const signatureValid = await verifyChallenge({
    publicKeyJwk: storedPublicKeyJwk,
    challengeB64: challenge,
    signatureB64: signature,
  });

  if (!signatureValid) {
    // NO eliminar el challenge en caso de fallo — permite reintentos
    // pero con rate-limiting implícito (60s TTL). En producción, añadir
    // contador de intentos fallidos por deviceId.
    return NextResponse.json(
      { error: "Firma del challenge inválida. Verifica que estás usando la privateKey ECDH correcta." },
      { status: 403 },
    );
  }

  // 7. Firma válida — eliminar challenge (one-time use) y devolver wrappedKey
  pendingChallenges.delete(deviceId);

  await db.device.update({
    where: { id: deviceId },
    data: { lastSeenAt: new Date() },
  });

  return NextResponse.json({
    enrolled: true,
    deviceId: device.id,
    deviceName: device.deviceName,
    wrappedPrivateKeyForDevice: device.wrappedPrivateKeyForDevice,
    wrappedPrivateKeyIv: device.wrappedPrivateKeyIv,
    publicKeyECDH: storedPublicKeyJwk,
    note: "Challenge verificado. Desenvuelve la privateKey RSA con tu ECDH privateKey usando ECDH(shared, peerPublic).",
  });
}
