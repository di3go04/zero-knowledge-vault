/**
 * =====================================================================
 * session-token.ts — Tokens de sesión HMAC-signed (HS256) con jti.
 * =====================================================================
 * Reemplazan al header x-user-id que era trivialmente forjable.
 *
 * MEJORA Fase 2: cada token incluye un `jti` (JWT ID único) que se
 * puede revocar en Redis. Esto permite logout server-side real.
 *
 * Formato: <payloadBase64>.<signatureBase64>
 *   - payload: { uid, jti, iat, exp } en JSON, base64url
 *   - signature: HMAC-SHA-256(payload, SESSION_SECRET) en base64url
 *
 * El token se envía como `Authorization: Bearer <token>`.
 *
 * Para logout server-side:
 *   1. Endpoint /api/auth/logout inserta jti en Redis con TTL = exp - now.
 *   2. Middleware requireAuth() verifica que jti NO esté en Redis.
 *
 * Si Redis no está disponible, usa Map in-memory (fallback para dev).
 * =====================================================================
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "zk-vault-session-secret-change-in-prod-min-32-chars!!";

const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 horas

export interface SessionPayload {
  uid: string; // userId
  jti: string; // JWT ID único — para blacklist en Redis
  iat: number; // issued-at (epoch seconds)
  exp: number; // expiration (epoch seconds)
}

// ---------------------------------------------------------------------------
// Blacklist adapter — Redis en producción, Map in-memory en dev
// ---------------------------------------------------------------------------
interface BlacklistAdapter {
  add(jti: string, ttlSeconds: number): Promise<void>;
  has(jti: string): Promise<boolean>;
}

let _adapter: BlacklistAdapter | null = null;

async function getBlacklistAdapter(): Promise<BlacklistAdapter> {
  if (_adapter) return _adapter;

  // En producción: usar Redis (ioredis) si REDIS_URL está definida.
  // En desarrollo: usar Map in-memory (suficiente para single-process).
  //
  // NOTA: ioredis se carga dinámicamente solo si REDIS_URL está presente
  // para evitar overhead en dev. Si no está, usamos Map in-memory.
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    try {
      // Dynamic import — solo se carga si Redis está configurado
      const ioredisModule: any = await import("ioredis").catch(() => null);
      if (ioredisModule) {
        const Redis = ioredisModule.default;
        const redis = new Redis(redisUrl, {
          maxRetriesPerRequest: 1,
          connectTimeout: 2000,
        });
        await redis.ping();
        _adapter = {
          async add(jti: string, ttlSeconds: number) {
            await redis.set(`bl:${jti}`, "1", "EX", ttlSeconds);
          },
          async has(jti: string) {
            const v = await redis.get(`bl:${jti}`);
            return v !== null;
          },
        };
        console.log("[blacklist] Redis conectado");
        return _adapter;
      }
    } catch (err) {
      console.warn("[blacklist] Redis no disponible, fallback a Map:", err);
    }
  }

  // Fallback: Map in-memory (no persiste entre reinicios, solo para dev)
  const memoryBlacklist = new Map<string, number>(); // jti -> exp timestamp
  _adapter = {
    async add(jti: string, ttlSeconds: number) {
      const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
      memoryBlacklist.set(jti, exp);
      setTimeout(() => {
        if (memoryBlacklist.get(jti) === exp) {
          memoryBlacklist.delete(jti);
        }
      }, ttlSeconds * 1000).unref?.();
    },
    async has(jti: string) {
      const exp = memoryBlacklist.get(jti);
      if (!exp) return false;
      if (exp <= Math.floor(Date.now() / 1000)) {
        memoryBlacklist.delete(jti);
        return false;
      }
      return true;
    },
  };
  console.log("[blacklist] Usando Map in-memory (dev fallback)");
  return _adapter;
}

// ---------------------------------------------------------------------------
// Serialización
// ---------------------------------------------------------------------------
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

function generateJti(): string {
  return randomBytes(16).toString("hex");
}

/**
 * Emite un token de sesión para el userId dado.
 * Incluye un jti único para blacklist server-side.
 */
export function issueSessionToken(userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    uid: userId,
    jti: generateJti(),
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
 * NO verifica la blacklist — eso lo hace verifySessionTokenWithBlacklist.
 */
export function verifySessionToken(token: string | null | undefined): SessionPayload | null {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;

  const expectedSig = sign(payloadB64);

  const sigBuf = Buffer.from(sig);
  const expectedBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expectedBuf.length) return null;
  if (!timingSafeEqual(sigBuf, expectedBuf)) return null;

  let payload: SessionPayload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64).toString("utf8"));
  } catch {
    return null;
  }

  if (
    typeof payload.uid !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number" ||
    typeof payload.exp !== "number"
  ) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (now >= payload.exp) return null;
  if (payload.iat > now + 60) return null;
  if (payload.uid.startsWith("decoy-")) return null;

  return payload;
}

/**
 * Verifica token + blacklist. Devuelve el payload solo si el token es
 * válido Y el jti no está en la blacklist.
 */
export async function verifySessionTokenWithBlacklist(
  token: string | null | undefined,
): Promise<SessionPayload | null> {
  const payload = verifySessionToken(token);
  if (!payload) return null;

  const adapter = await getBlacklistAdapter();
  if (await adapter.has(payload.jti)) {
    return null; // token revocado
  }

  return payload;
}

/**
 * Revoca un token insertando su jti en la blacklist.
 * El TTL es el tiempo restante hasta la expiración natural del token.
 */
export async function revokeSessionToken(token: string | null | undefined): Promise<boolean> {
  const payload = verifySessionToken(token);
  if (!payload) return false;

  const adapter = await getBlacklistAdapter();
  const ttlSeconds = payload.exp - Math.floor(Date.now() / 1000);
  if (ttlSeconds <= 0) return true; // ya expirado, no hay nada que revocar

  await adapter.add(payload.jti, ttlSeconds);
  return true;
}

/**
 * Extrae y verifica el token del header Authorization (con blacklist).
 * Devuelve el userId si el token es válido, o null.
 */
export async function extractUserIdFromAuth(authHeader: string | null): Promise<string | null> {
  if (!authHeader) return null;
  const match = /^Bearer\s+(.+)$/i.exec(authHeader);
  if (!match) return null;
  const payload = await verifySessionTokenWithBlacklist(match[1]);
  return payload?.uid ?? null;
}

export const SESSION_TTL = SESSION_TTL_SECONDS;
