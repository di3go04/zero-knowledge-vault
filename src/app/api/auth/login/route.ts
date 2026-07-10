/**
 * POST /api/auth/login
 *
 * NO recibe la contraseña maestra en el sentido de que NO la usa para nada.
 * Recibe solo el email y devuelve el material criptográfico PUBLICO necesario
 * para que el cliente pueda hacer PBKDF2 + descifrar localmente su llave
 * privada. El descifrado SIEMPRE ocurre en el cliente.
 *
 * Body: { email }
 * Response: { userId, email, name, kdfSalt, kdfIterations,
 *             encryptedPrivateKeyJwk, privateKeyIv, publicKeyJwk }
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

export async function POST(req: NextRequest) {
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const email = body?.email;
  if (typeof email !== "string" || !email) {
    return NextResponse.json({ error: "email requerido" }, { status: 400 });
  }

  const user = await db.user.findUnique({
    where: { email },
    include: { keyMaterial: true },
  });

  // Respuesta uniforme aunque el usuario no exista (evita enumeración)
  if (!user || !user.keyMaterial) {
    return NextResponse.json(
      {
        error:
          "Credenciales inválidas. Recuerda: el servidor nunca valida la contraseña, solo devuelve blobs.",
      },
      { status: 404 },
    );
  }

  return NextResponse.json({
    userId: user.id,
    email: user.email,
    name: user.name,
    kdfSalt: user.keyMaterial.kdfSalt,
    kdfIterations: user.keyMaterial.kdfIterations,
    encryptedPrivateKeyJwk: user.keyMaterial.encryptedPrivateKeyJwk,
    privateKeyIv: user.keyMaterial.privateKeyIv,
    publicKeyJwk: JSON.parse(user.keyMaterial.publicKeyJwk),
  });
}
