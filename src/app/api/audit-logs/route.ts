/**
 * /api/audit-logs
 *   GET  — Lista los logs del usuario autenticado (devuelve blobs cifrados).
 *   POST — Crea un nuevo log cifrado.
 *
 * MEJORA Fase 2 — Zero-Knowledge Logging.
 *
 * El cliente genera y cifra el log con AES-256-GCM usando una llave
 * derivada HKDF(masterKey, "audit-log-v1"). El servidor solo almacena
 * el blob cifrado + categoría (para indexación).
 *
 * Categorías válidas:
 *   "auth"     — login, logout, register, rotate
 *   "secret"   — create, read, delete
 *   "share"    — create, revoke, self-leave
 *   "device"   — enroll, revoke
 *   "recovery" — setup, recover
 */
import { NextRequest, NextResponse } from "next/server";
import { db } from "@/lib/db";
import {
  IV_EXPECTED_BYTES,
  MAX_BLOB_BYTES,
  validateBase64Blob,
} from "@/lib/crypto-server";
import { requireAuth } from "@/lib/auth-helper";

const VALID_CATEGORIES = ["auth", "secret", "share", "device", "recovery"];
const MAX_LOGS_PER_REQUEST = 200;

// ----------------------- GET (list) -----------------------
export async function GET(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  const url = req.nextUrl;
  const category = url.searchParams.get("category");
  const limit = Math.min(
    parseInt(url.searchParams.get("limit") ?? "100", 10),
    MAX_LOGS_PER_REQUEST,
  );

  const where: any = { userId };
  if (category && VALID_CATEGORIES.includes(category)) {
    where.eventCategory = category;
  }

  const logs = await db.auditLog.findMany({
    where,
    orderBy: { createdAt: "desc" },
    take: limit,
    select: {
      id: true,
      encryptedEvent: true,
      eventIv: true,
      eventCategory: true,
      createdAt: true,
    },
  });

  return NextResponse.json({ logs });
}

// ----------------------- POST (create) -----------------------
export async function POST(req: NextRequest) {
  const auth = await requireAuth(req);
  if (!auth.ok) return auth.response;
  const userId = auth.userId;

  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "JSON inválido" }, { status: 400 });
  }

  const { encryptedEvent, eventIv, eventCategory } = body ?? {};

  if (!validateBase64Blob(encryptedEvent, 1, MAX_BLOB_BYTES)) {
    return NextResponse.json(
      { error: `encryptedEvent debe ser base64 ≤ ${MAX_BLOB_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (!validateBase64Blob(eventIv, IV_EXPECTED_BYTES, IV_EXPECTED_BYTES)) {
    return NextResponse.json(
      { error: `eventIv debe ser base64 de ${IV_EXPECTED_BYTES} bytes` },
      { status: 400 },
    );
  }
  if (typeof eventCategory !== "string" || !VALID_CATEGORIES.includes(eventCategory)) {
    return NextResponse.json(
      { error: `eventCategory debe ser uno de: ${VALID_CATEGORIES.join(", ")}` },
      { status: 400 },
    );
  }

  const log = await db.auditLog.create({
    data: {
      userId,
      encryptedEvent,
      eventIv,
      eventCategory,
    },
  });

  return NextResponse.json({
    logId: log.id,
    createdAt: log.createdAt,
    note: "Log cifrado almacenado. Solo tú puedes descifrarlo con tu llave de auditoría (derivada de masterKey).",
  });
}
