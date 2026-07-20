/**
 * =====================================================================
 * rate-limit.ts — Rate limiter para endpoints sensibles.
 * =====================================================================
 * Implementación con adaptador dual: Redis (producción) o Map in-memory (dev).
 *
 * Políticas:
 *   - /api/auth/login: 5 intentos / 15 min / IP+email (anti-bruteforce offline)
 *   - /api/devices/enroll/poll/verify: 5 intentos / 1 min / IP+deviceId (anti-bruteforce ECDSA)
 *   - /api/devices/enroll/lookup: 5 intentos / 1 min / IP (anti-enumeración de códigos)
 *   - /api/devices/enroll/init: 3 intentos / 5 min / IP+email (anti-spam de dispositivos)
 *
 * MEJORA Módulo 2: preparado para Redis con fallback transparente.
 * =====================================================================
 */

interface RateLimitEntry {
  attempts: number[];
}

// ---------------------------------------------------------------------------
// Store adapter — Redis en producción, Map in-memory en dev
// ---------------------------------------------------------------------------
interface RateLimitStore {
  get(key: string): Promise<number[] | null>;
  set(key: string, attempts: number[], ttlMs: number): Promise<void>;
  delete(key: string): Promise<void>;
}

let _store: RateLimitStore | null = null;

async function getStore(): Promise<RateLimitStore> {
  if (_store) return _store;

  const redisUrl = process.env.REDIS_URL;
  if (redisUrl) {
    try {
      const ioredisModule: any = await import("ioredis").catch(() => null);
      if (ioredisModule) {
        const Redis = ioredisModule.default;
        const redis = new Redis(redisUrl, {
          maxRetriesPerRequest: 1,
          connectTimeout: 2000,
          enableOfflineQueue: false,
        });
        await redis.ping();
        console.log("[rate-limit] Redis conectado");

        _store = {
          async get(key: string) {
            try {
              const v = await redis.get(`rl:${key}`);
              return v ? JSON.parse(v) : null;
            } catch {
              return memoryStore.get(key) ?? null;
            }
          },
          async set(key: string, attempts: number[], ttlMs: number) {
            try {
              await redis.set(`rl:${key}`, JSON.stringify(attempts), "PX", ttlMs);
            } catch {
              memoryStore.set(key, attempts, ttlMs);
            }
          },
          async delete(key: string) {
            try {
              await redis.del(`rl:${key}`);
            } catch {
              // no-op
            }
            memoryStore.delete(key);
          },
        };
        return _store;
      }
    } catch (err: any) {
      console.warn("[rate-limit] Redis unavailable — fallback to Map");
    }
  }

  // Map in-memory (dev)
  _store = {
    async get(key: string) {
      return memoryStore.get(key) ?? null;
    },
    async set(key: string, attempts: number[], ttlMs: number) {
      memoryStore.set(key, attempts, ttlMs);
    },
    async delete(key: string) {
      memoryStore.delete(key);
    },
  };
  console.log("[rate-limit] Usando Map in-memory");
  return _store;
}

// Map in-memory compartido (fallback)
const memoryMap = new Map<string, RateLimitEntry>();
const memoryStore = {
  get(key: string): number[] | null {
    const entry = memoryMap.get(key);
    if (!entry) return null;
    return entry.attempts;
  },
  set(key: string, attempts: number[], ttlMs: number) {
    memoryMap.set(key, { attempts });
    // Cleanup programado
    setTimeout(() => {
      if (memoryMap.get(key)?.attempts === attempts) {
        memoryMap.delete(key);
      }
    }, ttlMs).unref?.();
  },
  delete(key: string) {
    memoryMap.delete(key);
  },
};

// ---------------------------------------------------------------------------
// Políticas predefinidas
// ---------------------------------------------------------------------------
export const RATE_LIMIT_POLICIES = {
  login: { maxAttempts: 5, windowMs: 15 * 60 * 1000 }, // 5 / 15 min
  enrollVerify: { maxAttempts: 5, windowMs: 60 * 1000 }, // 5 / 1 min
  enrollLookup: { maxAttempts: 5, windowMs: 60 * 1000 }, // 5 / 1 min
  enrollInit: { maxAttempts: 3, windowMs: 5 * 60 * 1000 }, // 3 / 5 min
  default: { maxAttempts: 5, windowMs: 15 * 60 * 1000 },
} as const;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

// Cleanup in-memory cada 5 min
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
let lastCleanup = Date.now();
function cleanupOldEntries(windowMs: number) {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = now;
  const cutoff = now - windowMs;
  for (const [key, entry] of memoryMap) {
    entry.attempts = entry.attempts.filter((t) => t > cutoff);
    if (entry.attempts.length === 0) {
      memoryMap.delete(key);
    }
  }
}

/**
 * Verifica si una acción está permitida bajo el rate limit.
 * Registra el intento actual (siempre, incluso si es denegado).
 *
 * ASYNC: usa el store (Redis o Map) que puede requerir I/O.
 */
export async function checkRateLimit(
  key: string,
  maxAttempts: number = 5,
  windowMs: number = 15 * 60 * 1000,
): Promise<RateLimitResult> {
  cleanupOldEntries(windowMs);

  const store = await getStore();
  const now = Date.now();
  const cutoff = now - windowMs;

  // Obtener intentos existentes
  let attempts = (await store.get(key)) ?? [];
  attempts = attempts.filter((t) => t > cutoff);

  if (attempts.length >= maxAttempts) {
    const oldest = Math.min(...attempts);
    const retryAfterMs = oldest + windowMs - now;
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    };
  }

  // Registrar el intento actual
  attempts.push(now);
  await store.set(key, attempts, windowMs);

  return {
    allowed: true,
    remaining: maxAttempts - attempts.length,
    retryAfterSeconds: 0,
  };
}

/**
 * Resetea el rate limit para una clave (ej. tras login exitoso).
 */
export async function resetRateLimit(key: string): Promise<void> {
  const store = await getStore();
  await store.delete(key);
}

/**
 * Helper: obtener IP del cliente desde headers comunes.
 */
export function getClientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  const xri = req.headers.get("x-real-ip");
  if (xri) return xri;
  return "unknown";
}

/**
 * Helper: construir respuesta 429 estándar con headers de rate limit.
 */
export function rateLimitResponse(retryAfterSeconds: number, remaining: number = 0): Response {
  return new Response(
    JSON.stringify({
      error: "Demasiados intentos. Intenta más tarde.",
      retryAfter: retryAfterSeconds,
    }),
    {
      status: 429,
      headers: {
        "Content-Type": "application/json",
        "Retry-After": String(retryAfterSeconds),
        "X-RateLimit-Remaining": String(remaining),
        "X-RateLimit-Reset": String(retryAfterSeconds),
      },
    },
  );
}
