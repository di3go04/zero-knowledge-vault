/**
 * POST /api/auth/register
 *
 * Recibe EXCLUSIVAMENTE blobs cifrados y llaves públicas.
 * Validaciones server-side (Ciclo 1 de auditoría):
 *   - kdfIterations ∈ [310_000, 1_000_000] (anti-DoS + mínimo OWASP)
 *   - kdfSalt decodificado ∈ [16, 64] bytes
 *   - privateKeyIv decodificado = 12 bytes exactos
 *   - encryptedPrivateKeyJwk ≤ 64 KiB
 *   - publicKeyJwk ≤ 4 KiB y contiene kty, n, e
 *   - popSignature ≤ 512 bytes y es RSA-PSS válida sobre
 *     {email, publicKeyFingerprint, kdfSalt}
 *
 * El servidor NO descifra nada. Solo verifica la firma PoP con la
 * publicKey que el cliente declara — esto prueba que el cliente posee
 * la privateKey correspondiente, previniendo sustitución de publicKey.
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  KDF_ITERATIONS_MAX,
  KDF_ITERATIONS_MIN,
  IV_EXPECTED_BYTES,
  MAX_BLOB_BYTES,
  MAX_JWK_BYTES,
  SALT_MAX_BYTES,
  SALT_MIN_BYTES,
  publicKeyFingerprint,
  validateBase64Blob,
  validateKdfIterations,
  verifyPopSignature,
} from "@/lib/crypto-server";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const EMAIL_MAX_LEN = 320; // RFC 5321
const NAME_MAX_LEN = 100;

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const {
    email,
    name,
    kdfSalt,
    kdfIterations,
    publicKeyJwk,
    encryptedPrivateKeyJwk,
    privateKeyIv,
    popSignature,
  } = body ?? {};

  // -------- email --------
  if (
    typeof email !== "string" ||
    email.length > EMAIL_MAX_LEN ||
    !EMAIL_RE.test(email)
  ) {
    return NextResponse.json({ error: "email inválido" }, { status: 400 });
  }
  const normalizedEmail = email.toLowerCase().trim();

  // -------- name --------
  if (
    name !== undefined &&
    name !== null &&
    (typeof name !== "string" || name.length > NAME_MAX_LEN)
  ) {
    return NextResponse.json({ error: "name inválido" }, { status: 400 });
  }

  // -------- kdfIterations --------
  if (!validateKdfIterations(kdfIterations)) {
    return NextResponse.json(
      {
        error: `kdfIterations debe ser entero entre ${KDF_ITERATIONS_MIN} y ${KDF_ITERATIONS_MAX}`,
      },
      { status: 400 },
    );
  }

  // -------- kdfSalt: base64 + longitud decodificada --------
  if (!validateBase64Blob(kdfSalt, SALT_MIN_BYTES, SALT_MAX_BYTES)) {
    return NextResponse.json(
      {
        error: `kdfSalt debe ser base64 y decodificar entre ${SALT_MIN_BYTES} y ${SALT_MAX_BYTES} bytes`,
      },
      { status: 400 },
    );
  }

  // -------- privateKeyIv: exactamente 12 bytes --------
  if (!validateBase64Blob(privateKeyIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `privateKeyIv debe ser base64 de exactamente ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }

  // -------- encryptedPrivateKeyJwk: ≤ 64 KiB --------
  if (!validateBase64Blob(encryptedPrivateKeyJwk, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `encryptedPrivateKeyJwk debe ser base64 ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }

  // -------- publicKeyJwk: estructura + tamaño --------
  if (
    !publicKeyJwk ||
    typeof publicKeyJwk !== "object" ||
    Array.isArray(publicKeyJwk)
  ) {
    return NextResponse.json(
      { error: "publicKeyJwk debe ser un objeto JsonWebKey" },
      { status: 400 },
    );
  }
  const jwkStr = JSON.stringify(publicKeyJwk);
  if (jwkStr.length > MAX_JWK_BYTES) {
    return NextResponse.json(
      { error: `publicKeyJwk excede ${MAX_JWK_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (
    publicKeyJwk.kty !== "RSA" ||
    typeof publicKeyJwk.n !== "string" ||
    typeof publicKeyJwk.e !== "string"
  ) {
    return NextResponse.json(
      { error: "publicKeyJwk debe ser RSA con kty, n y e" },
      { status: 400 },
    );
  }

  // -------- popSignature: base64 ≤ 512 bytes --------
  if (!validateBase64Blob(popSignature, 1, 512)) {
    return NextResponse.json(
      { error: "popSignature debe ser base64 (firma RSA-PSS)" },
      { status: 400 },
    );
  }

  // -------- Verificar PoP ANTES de tocar la BD --------
  // Calcular fingerprint server-side (no confiamos en la del cliente)
  const serverFingerprint = await publicKeyFingerprint(publicKeyJwk as Record<string, unknown>);

  const popValid = await verifyPopSignature({
    publicKeyJwk: publicKeyJwk as JsonWebKey,
    signatureB64: popSignature,
    email: normalizedEmail,
    fingerprintHex: serverFingerprint,
    kdfSaltB64: kdfSalt,
  });

  if (!popValid) {
    return NextResponse.json(
      {
        error:
          "Proof-of-Possession inválida: la firma RSA-PSS no corresponde a la publicKey declarada. Posible intento de sustitución de llave.",
      },
      { status: 403 },
    );
  }

  // -------- Verificar unicidad --------
  const existing = await db.user.findUnique({ where: { email: normalizedEmail } });
  if (existing) {
    return NextResponse.json({ error: "El email ya está registrado" }, { status: 409 });
  }

  // -------- Persistir --------
  const user = await db.user.create({
    data: {
      email: normalizedEmail,
      name:
        typeof name === "string" && name.trim() ? name.trim().slice(0, NAME_MAX_LEN) : null,
      keyMaterial: {
        create: {
          kdfSalt,
          kdfIterations,
          publicKeyJwk: jwkStr,
          publicKeyFingerprint: serverFingerprint,
          popSignature,
          popSignatureHash: "SHA-256",
          encryptedPrivateKeyJwk,
          privateKeyIv,
        },
      },
    },
    include: { keyMaterial: true },
  });

  return NextResponse.json({
    userId: user.id,
    email: user.email,
    name: user.name,
    publicKeyFingerprint: serverFingerprint,
    createdAt: user.createdAt,
  });
}
