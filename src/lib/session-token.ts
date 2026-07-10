/**
 * =====================================================================
 * session-token.ts — Tokens de sesión HMAC-signed (HS256).
 * =====================================================================
 * Reemplazan al header x-user-id que era trivialmente forjable.
 *
 * Formato: <payloadBase64>.<signatureBase64>
 *   - payload: { uid, iat, exp } en JSON, base64url
 *   - signature: HMAC-SHA-256(payload, SESSION_SECRET) en base64url
 *
 * El token se envía como `Authorization: Bearer <token>`.
 * El servidor lo valida en cada request autenticada.
 *
 * No es un JWT estándar (no usamos librerías externas), pero sigue
 * la misma estructura. Stateless: no requiere almacenamiento server-side,
 * pero NO puede revocarse individualmente sin maintain una blacklist.
 * Para esta demo, la expiración corta (8h) es suficiente. En producción
 * se debería añadir una blacklist en Redis o usar sessions opacas.
 * =====================================================================
 */
import { createHmac, timingSafeEqual } from "node:crypto";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "zk-vault-session-secret-change-in-prod-min-32-chars!!";

const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 horas

export interface SessionPayload {
  uid: string; // userId
  iat: number; // issued-at (epoch seconds)
  exp: number; // expiration (epoch seconds)
}

function base64UrlEncode(buf: Buffer | string): string {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return b
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(s: string): Buffer {
  let str = s.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Buffer.from(str, "base64");
}

function sign(data: string): string {
  return base64UrlEncode(createHmac("sha256", SESSION_SECRET).update(data).digest());
}

/**
 * Emite un token de sesión para el userId dado.
 */
export function issueSessionToken(userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    uid: userId,
    iat: now,
    exp: now + SESSION_TTL_SECONDS,
  };
  const payloadB64 = base64UrlEncode(JSON.stringify(payload));
  const sig = sign(payloadB64);
  return `${payloadB64}.${sig}`;
}

/**
 * Verifica un token de sesión. Devuelve el payload si es válido y no
 * ha expirado, o null en caso contrario.
 *
 * Usa timingSafeEqual para prevenir timing attacks en la comparación
 * de la firma.
 */
export function verifySessionToken(token: string | null | undefined): SessionPayload | null {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;

  // Re-calcular la firma esperada
  const expectedSig = sign(payloadB64);

  // timingSafeEqual requiere buffers de igual longitud
  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(sigBuf, expectedBuf)) return null;

  // Decodificar payload
  let payload: SessionPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64).toString("utf8"));
  } catch {
    return null;
  }

  // Validar campos
  if (
    typeof payload.uid !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number"
  ) {
    return null;
  }

  // Validar expiración
  const now = Math.floor(Date.now() / 1000);
  if (now >= payload.exp) return null;

  // Validar que iat no sea en el futuro (clock skew tolerance: 60s)
  if (payload.iat > now + 60) return null;

  // Rechazar tokens "decoy"
  if (payload.uid.startsWith("decoy-")) return null;

  return payload;
}

/**
 * Extrae y verifica el token del header Authorization.
 * Devuelve el userId si el token es válido, o null.
 */
export function extractUserIdFromAuth(authHeader: string | null): string | null {
  if (!authHeader) return null;
  const match = /^Bearer\s+(.+)$/i.exec(authHeader);
  if (!match) return null;
  const payload = verifySessionToken(match[1]);
  return payload?.uid ?? null;
}

export const SESSION_TTL = SESSION_TTL_SECONDS;
