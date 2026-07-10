/**
 * POST /api/auth/login
 *
 * Recibe solo el email y devuelve el material criptográfico PÚBLICO
 * necesario para que el cliente haga PBKDF2 + descifre localmente su
 * llave privada.
 *
 * MEJORA Ciclo 1 — Anti-enumeración:
 *   Si el email NO existe, se devuelve una respuesta DECOY con
 *   material criptográfico determinista derivado del email (HMAC-SHA-256
 *   con clave del servidor). La respuesta tiene EXACTAMENTE la misma
 *   estructura que la de un usuario real, de modo que el atacante no
 *   puede distinguir "email no registrado" de "contraseña incorrecta".
 *   El cliente ejecutará PBKDF2 + AES-GCM y obtendrá un error de tag
 *   GCM inválido — mismo UX que contraseña incorrecta.
 *
 * Body: { email }
 * Response (real o decoy):
 *   { userId, email, name, kdfSalt, kdfIterations,
 *     encryptedPrivateKeyJwk, privateKeyIv, publicKeyJwk,
 *     publicKeyFingerprint, isDecoy? }
 *
 * El campo `isDecoy` se incluye SOLO cuando es decoy, para que el
 * cliente sepa que el fallo posterior de descifrado es esperado.
 * (Esto NO filtra al atacante porque el atacante ya sabe que pidió
 * un email inventado; el campo es para diagnóstico interno del cliente.)
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  generateDecoyLoginResponse,
  publicKeyFingerprint,
} from "@/lib/crypto-server";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const email = body?.email;
  if (typeof email !== "string" || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "email inválido" }, { status: 400 });
  }
  const normalizedEmail = email.toLowerCase().trim();

  const user = await db.user.findUnique({
    where: { email: normalizedEmail },
    include: { keyMaterial: true },
  });

  // -------- CASO 1: usuario real --------
  if (user && user.keyMaterial) {
    const fingerprint = user.keyMaterial.publicKeyFingerprint;
    return NextResponse.json({
      userId: user.id,
      email: user.email,
      name: user.name,
      kdfSalt: user.keyMaterial.kdfSalt,
      kdfIterations: user.keyMaterial.kdfIterations,
      encryptedPrivateKeyJwk: user.keyMaterial.encryptedPrivateKeyJwk,
      privateKeyIv: user.keyMaterial.privateKeyIv,
      publicKeyJwk: JSON.parse(user.keyMaterial.publicKeyJwk),
      publicKeyFingerprint: fingerprint,
      isDecoy: false,
    });
  }

  // -------- CASO 2: usuario inexistente → DECOY --------
  // Generamos material criptográficamente determinista derivado del email.
  // El cliente ejecutará PBKDF2 (CPU cost) y luego AES-GCM fallará con
  // tag inválido — mismo flujo que contraseña incorrecta. El atacante
  // no puede distinguir ambos casos.
  const decoy = generateDecoyLoginResponse(normalizedEmail);
  return NextResponse.json({
    userId: `decoy-${normalizedEmail}`,
    email: normalizedEmail,
    name: null,
    kdfSalt: decoy.kdfSalt,
    kdfIterations: decoy.kdfIterations,
    encryptedPrivateKeyJwk: decoy.encryptedPrivateKeyJwk,
    privateKeyIv: decoy.privateKeyIv,
    publicKeyJwk: decoy.publicKeyJwk,
    publicKeyFingerprint: await publicKeyFingerprint(decoy.publicKeyJwk as Record<string, unknown>),
    isDecoy: true,
  });
}
