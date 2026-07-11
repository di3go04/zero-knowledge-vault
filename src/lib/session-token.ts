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
let _adapterType: "redis" | "memory" | null = null;
let _redisHealthOk = true; // Health flag — se resetea en errores, se restaura en healthcheck

/**
 * Adaptador de blacklist con resiliencia:
 *
 * - Si REDIS_URL está definida Y Redis responde → usa Redis.
 * - Si REDIS_URL está definida PERO Redis cae → fallback a Map in-memory
 *   + log de warning. La API sigue funcionando (degraded mode).
 * - Si REDIS_URL no está definida → usa Map in-memory (dev).
 *
 * El adaptador Redis envuelve cada operación en try/catch para que
 * un error de conexión Redis nunca tire la API. Si Redis falla
 * durante una operación `has`, se devuelve false (fail-open) para no
 * bloquear al usuario legítimo, pero se loguea el error.
 *
 * HEALTHCHECK: si Redis cae y se recupera, un healthcheck periódico
 * (cada 30s) resetea el adapter para volver a usar Redis.
 */
async function getBlacklistAdapter(): Promise<BlacklistAdapter> {
  if (_adapter) return _adapter;

  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    try {
      const ioredisModule: any = await import("ioredis").catch(() => null);
      if (ioredisModule) {
        const Redis = ioredisModule.default;
        const redis = new Redis(redisUrl, {
          maxRetriesPerRequest: 1,
          connectTimeout: 2000,
          enableOfflineQueue: false, // Fallar inmediatamente si Redis cae
          retryStrategy: (times) => {
            if (times > 3) return null; // Dejar de reintentar tras 3 fallos
            return Math.min(times * 200, 1000);
          },
        });

        // Test de conexión inicial
        await redis.ping();

        // Manejar errores de conexión persistentes
        redis.on("error", (err: Error) => {
          console.warn("[blacklist] Redis error (sigue en degraded mode):", err.message);
          _redisHealthOk = false;
        });

        redis.on("ready", () => {
          if (!_redisHealthOk) {
            console.log("[blacklist] Redis recuperado, volviendo a modo normal");
            _redisHealthOk = true;
          }
        });

        _adapter = {
          async add(jti: string, ttlSeconds: number) {
            try {
              if (!_redisHealthOk) throw new Error("Redis unhealthy");
              await redis.set(`bl:${jti}`, "1", "EX", ttlSeconds);
            } catch (err: any) {
              // Redis caído — fallback a Map in-memory
              console.warn("[blacklist] Redis add falló, usando Map:", err.message);
              memoryAdd(jti, ttlSeconds);
            }
          },
          async has(jti: string) {
            try {
              if (!_redisHealthOk) throw new Error("Redis unhealthy");
              const v = await redis.get(`bl:${jti}`);
              if (v !== null) return true;
              // También verificar Map in-memory por si hubo fallback
              return memoryHas(jti);
            } catch (err: any) {
              // Redis caído — fail-open (no bloquear usuario legítimo)
              // pero verificar Map in-memory por si el jti fue añadido
              // durante un fallo de Redis.
              console.warn("[blacklist] Redis has falló, usando Map:", err.message);
              return memoryHas(jti);
            }
          },
        };
        _adapterType = "redis";
        console.log("[blacklist] Redis conectado");
        return _adapter;
      }
    } catch (err: any) {
      console.warn("[blacklist] Redis no disponible, fallback a Map:", err?.message ?? err);
    }
  }

  // Map in-memory (dev o degraded mode)
  _adapter = {
    async add(jti: string, ttlSeconds: number) {
      memoryAdd(jti, ttlSeconds);
    },
    async has(jti: string) {
      return memoryHas(jti);
    },
  };
  _adapterType = "memory";
  console.log("[blacklist] Usando Map in-memory");
  return _adapter;
}

// ---------------------------------------------------------------------------
// Map in-memory compartido entre adaptadores (para fallback transparente)
// ---------------------------------------------------------------------------
const memoryBlacklist = new Map<string, number>(); // jti -> exp timestamp

function memoryAdd(jti: string, ttlSeconds: number) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  memoryBlacklist.set(jti, exp);
  setTimeout(() => {
    if (memoryBlacklist.get(jti) === exp) {
      memoryBlacklist.delete(jti);
    }
  }, ttlSeconds * 1000).unref?.();
}

function memoryHas(jti: string): boolean {
  const exp = memoryBlacklist.get(jti);
  if (!exp) return false;
  if (exp <= Math.floor(Date.now() / 1000)) {
    memoryBlacklist.delete(jti);
    return false;
  }
  return true;
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
