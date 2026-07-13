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
import { requireAuth } from "@/lib/auth-helper";
import { createAuditLogSchema, validatePayload } from "@/lib/validation-schemas";

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

  const validation = validatePayload(createAuditLogSchema, body);
  if (!validation.success) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }
  const { encryptedEvent, eventIv, eventCategory } = validation.data;

  //
  const lastLog = await db.auditLog.findFirst({
    where: { userId },
    orderBy: { createdAt: "desc" },
    select: { logHash: true },
  });
  const prevHash = lastLog?.logHash ?? null;

  // Calcular hash del log actual
  const { computeLogHash } = await import("@/lib/hash-chain-logs");
  const createdAt = new Date().toISOString();
  const logHash = computeLogHash(prevHash, encryptedEvent, createdAt);

  const log = await db.auditLog.create({
    data: {
      userId,
      encryptedEvent,
      eventIv,
      eventCategory,
      prevHash,
      logHash,
    },
  });

  return NextResponse.json({
    logId: log.id,
    createdAt: log.createdAt,
    note: "Log cifrado almacenado. Solo tú puedes descifrarlo con tu llave de auditoría (derivada de masterKey).",
  });
}
