import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import { generateLoginOptions } from "@/lib/webauthn";
import { loginSchema, validatePayload } from "@/lib/validation-schemas";
import { logger } from "@/lib/logger";

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const validation = validatePayload(loginSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  const email = validation.data.email;
  const normalizedEmail = email.toLowerCase().trim();

  const user = await db.user.findUnique({
    where: { email: normalizedEmail },
    select: { id: true },
  });
  if (!user) {
    return NextResponse.json(
      { error: "No hay passkeys registradas para este usuario" },
      { status: 404 },
    );
  }

  const passkeys = await db.passkey.findMany({
    where: { userId: user.id },
    select: { credentialId: true, transports: true },
  });

  if (passkeys.length === 0) {
    return NextResponse.json(
      { error: "No hay passkeys registradas para este usuario" },
      { status: 404 },
    );
  }

  const parsedTransports = passkeys.map((p) => {
    try {
      return { credentialId: p.credentialId, transports: JSON.parse(p.transports) as string[] };
    } catch {
      return { credentialId: p.credentialId, transports: ["internal"] as string[] };
    }
  });

  const options = generateLoginOptions(user.id, parsedTransports);

  logger.info({ userId: user.id }, "webauthn login started");
  return NextResponse.json(options);
}
