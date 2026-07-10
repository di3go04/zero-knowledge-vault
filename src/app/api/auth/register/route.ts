/**
 * POST /api/auth/register
 *
 * Recibe EXCLUSIVAMENTE blobs cifrados y llaves públicas.
 * El servidor no tiene forma de descifrar nada de lo que recibe.
 *
 * Body:
 *   {
 *     email, name?,
 *     kdfSalt (base64), kdfIterations (int),
 *     publicKeyJwk (JsonWebKey),
 *     encryptedPrivateKeyJwk (base64), privateKeyIv (base64)
 *   }
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const isBase64 = (s: unknown): s is string =>
  typeof s === "string" && s.length > 0 && /^[A-Za-z0-9+/=_-]+$/.test(s);

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
  } = body ?? {};

  if (!email || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "email inválido" }, { status: 400 });
  }
  if (typeof kdfIterations !== "number" || kdfIterations < 100_000) {
    return NextResponse.json(
      { error: "kdfIterations debe ser >= 100000" },
      { status: 400 },
    );
  }
  if (!isBase64(kdfSalt)) {
    return NextResponse.json({ error: "kdfSalt debe ser base64" }, { status: 400 });
  }
  if (!isBase64(encryptedPrivateKeyJwk)) {
    return NextResponse.json(
      { error: "encryptedPrivateKeyJwk debe ser base64" },
      { status: 400 },
    );
  }
  if (!isBase64(privateKeyIv)) {
    return NextResponse.json({ error: "privateKeyIv debe ser base64" }, { status: 400 });
  }
  if (
    !publicKeyJwk ||
    typeof publicKeyJwk !== "object" ||
    !publicKeyJwk.n ||
    !publicKeyJwk.e
  ) {
    return NextResponse.json(
      { error: "publicKeyJwk debe ser un JsonWebKey RSA válido" },
      { status: 400 },
    );
  }

  const existing = await db.user.findUnique({ where: { email } });
  if (existing) {
    return NextResponse.json({ error: "El email ya está registrado" }, { status: 409 });
  }

  const user = await db.user.create({
    data: {
      email,
      name: typeof name === "string" && name.trim() ? name.trim() : null,
      keyMaterial: {
        create: {
          kdfSalt,
          kdfIterations,
          publicKeyJwk: JSON.stringify(publicKeyJwk),
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
    createdAt: user.createdAt,
  });
}
