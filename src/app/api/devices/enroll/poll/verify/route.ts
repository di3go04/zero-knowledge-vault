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
} from "@/lib/crypto/server";
import { enrollVerifySchema, validatePayload } from "@/lib/validation-schemas";
import { checkRateLimit, getClientIp, RATE_LIMIT_POLICIES } from "@/lib/rate-limit";
import { getChallenge, deleteChallenge } from "@/lib/challenge-store";

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

  // -------- Rate limit anti-bruteforce ECDSA --------
  // 5 intentos / 1 min / IP+deviceId. Previene que un atacante pruebe
  // miles de firmas ECDSA por segundo.
  const ip = getClientIp(req);
  const rlKey = `enroll-verify:${ip}:${deviceId}`;
  const rl = await checkRateLimit(
    rlKey,
    RATE_LIMIT_POLICIES.enrollVerify.maxAttempts,
    RATE_LIMIT_POLICIES.enrollVerify.windowMs,
  );
  if (!rl.allowed) {
    return NextResponse.json(
      {
        error: "Demasiados intentos de verificación. Espera antes de reintentar.",
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

  // 1. Buscar challenge pendiente en el store (Redis o Map)
  const pending = await getChallenge(deviceId);
  if (!pending) {
    // No revelar si el challenge existía o no
    return NextResponse.json(
      { error: "Challenge inválido, expirado o ya usado" },
      { status: 403 },
    );
  }

  // 2. Verificar que el challenge enviado coincide con el almacenado
  // (evita que el atacante use un challenge distinto)
  if (pending.challenge !== challenge) {
    return NextResponse.json(
      { error: "Challenge no coincide con el emitido" },
      { status: 403 },
    );
  }

  // 3. Buscar dispositivo
  const device = await db.device.findUnique({ where: { id: deviceId } });
  if (!device) {
    await deleteChallenge(deviceId);
    return NextResponse.json({ error: "Dispositivo no encontrado" }, { status: 404 });
  }

  if (device.revokedAt) {
    await deleteChallenge(deviceId);
    return NextResponse.json({ error: "Dispositivo revocado" }, { status: 403 });
  }

  if (!device.wrappedPrivateKeyForDevice || device.wrappedPrivateKeyIv === "") {
    await deleteChallenge(deviceId);
    return NextResponse.json({ error: "Enrollment no completado" }, { status: 400 });
  }

  // 4. Verificar fingerprint de la publicKey ECDH (defense in depth)
  const storedPublicKeyJwk = JSON.parse(device.publicKeyECDH) as JsonWebKey;
  const serverFingerprint = await publicKeyFingerprint(
    storedPublicKeyJwk as Record<string, unknown>,
  );
  if (serverFingerprint !== device.publicKeyECDHFingerprint) {
    await deleteChallenge(deviceId);
    return NextResponse.json(
      { error: "Fingerprint de publicKey ECDH inconsistente — posible manipulación de BD" },
      { status: 500 },
    );
  }

  // 5. Verificar firma ECDSA del challenge
  const signatureValid = await verifyChallenge({
    publicKeyJwk: storedPublicKeyJwk,
    challengeB64: challenge,
    signatureB64: signature,
  });

  if (!signatureValid) {
    // NO eliminar el challenge en caso de fallo — permite reintentos
    // pero con rate-limiting (5/min) que previene bruteforce.
    return NextResponse.json(
      { error: "Firma del challenge inválida. Verifica que estás usando la privateKey ECDH correcta." },
      { status: 403 },
    );
  }

  // 6. Firma válida — eliminar challenge (one-time use) y devolver wrappedKey
  await deleteChallenge(deviceId);

  await db.device.update({
    where: { id: deviceId },
    data: { lastSeenAt: new Date() },
  });

  // 7. Verificar que enrollerPublicKeyECDH esté guardado (A completó el enrollment)
  if (!device.enrollerPublicKeyECDH) {
    return NextResponse.json(
      { error: "El dispositivo autorizador aún no ha completado el enrollment" },
      { status: 400 },
    );
  }

  const enrollerPublicKeyECDH = JSON.parse(device.enrollerPublicKeyECDH) as JsonWebKey;

  return NextResponse.json({
    enrolled: true,
    deviceId: device.id,
    deviceName: device.deviceName,
    wrappedPrivateKeyForDevice: device.wrappedPrivateKeyForDevice,
    wrappedPrivateKeyIv: device.wrappedPrivateKeyIv,
    publicKeyECDH: storedPublicKeyJwk,
    enrollerPublicKeyECDH,
    note: "Challenge verificado. Desenvuelve la privateKey RSA derivando ECDH(B.privateKey, enrollerPublicKeyECDH).",
  });
}
