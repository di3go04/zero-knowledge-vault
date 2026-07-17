/**
 * =====================================================================
 * challenge-store.ts — Store de challenges ECDSA para Enroll Device.
 * =====================================================================
 * Adaptador dual: Redis (producción multi-instancia) o Map in-memory (dev).
 *
 * Los challenges son nonces de 32 bytes generados por el servidor cuando
 * el Dispositivo B hace poll. El Dispositivo B debe firmar el challenge
 * con su privateKey ECDH (ECDSA P-256) para recibir la wrappedPrivateKey.
 *
 * TTL estricto de 60 segundos — un challenge no reutilizable.
 *
 * MEJORA Módulo 3: migración de globalThis Map a Redis con fallback.
 * =====================================================================
 */

import { env } from "@/lib/env";

interface ChallengeEntry {
  challenge: string; // base64
  expiresAt: number; // epoch ms
}

interface ChallengeStore {
  save(deviceId: string, challenge: string, ttlMs: number): Promise<void>;
  get(deviceId: string): Promise<ChallengeEntry | null>;
  delete(deviceId: string): Promise<void>;
}

let _store: ChallengeStore | null = null;

// Fallback Map in-memory (compartido vía globalThis para single-process)
const globalForChallenges = globalThis as unknown as {
  __pendingDeviceChallenges?: Map<string, ChallengeEntry>;
};
if (!globalForChallenges.__pendingDeviceChallenges) {
  globalForChallenges.__pendingDeviceChallenges = new Map();
}
const memoryMap = globalForChallenges.__pendingDeviceChallenges;

// Cleanup in-memory cada 60s
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of memoryMap) {
      if (entry.expiresAt <= now) memoryMap.delete(key);
    }
  }, 60_000).unref?.();
}

/**
 * Obtiene el store de challenges. Usa Redis si REDIS_URL está definida,
 * si no, usa Map in-memory.
 */
async function getStore(): Promise<ChallengeStore> {
  if (_store) return _store;

  const redisUrl = env.REDIS_URL;
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
        console.log("[challenge-store] Redis conectado");

        _store = {
          async save(deviceId: string, challenge: string, ttlMs: number) {
            try {
              const entry: ChallengeEntry = {
                challenge,
                expiresAt: Date.now() + ttlMs,
              };
              await redis.set(
                `challenge:${deviceId}`,
                JSON.stringify(entry),
                "PX",
                ttlMs,
              );
            } catch (err: any) {
              // Redis caído — fallback a Map
              console.warn("[challenge-store] Redis save falló, usando Map:", err.message);
              memoryMap.set(deviceId, {
                challenge,
                expiresAt: Date.now() + ttlMs,
              });
            }
          },
          async get(deviceId: string) {
            try {
              const v = await redis.get(`challenge:${deviceId}`);
              if (!v) {
                // También verificar Map por si hubo fallback
                const mem = memoryMap.get(deviceId);
                if (mem && mem.expiresAt > Date.now()) return mem;
                return null;
              }
              return JSON.parse(v) as ChallengeEntry;
            } catch (err: any) {
              console.warn("[challenge-store] Redis get falló, usando Map:", err.message);
              const mem = memoryMap.get(deviceId);
              if (mem && mem.expiresAt > Date.now()) return mem;
              return null;
            }
          },
          async delete(deviceId: string) {
            try {
              await redis.del(`challenge:${deviceId}`);
            } catch {
              // no-op
            }
            memoryMap.delete(deviceId);
          },
        };
        return _store;
      }
    } catch (err: any) {
      console.warn("[challenge-store] Redis no disponible, fallback a Map:", err?.message);
    }
  }

  // Map in-memory (dev)
  _store = {
    async save(deviceId: string, challenge: string, ttlMs: number) {
      memoryMap.set(deviceId, {
        challenge,
        expiresAt: Date.now() + ttlMs,
      });
    },
    async get(deviceId: string) {
      const entry = memoryMap.get(deviceId);
      if (!entry) return null;
      if (entry.expiresAt <= Date.now()) {
        memoryMap.delete(deviceId);
        return null;
      }
      return entry;
    },
    async delete(deviceId: string) {
      memoryMap.delete(deviceId);
    },
  };
  console.log("[challenge-store] Usando Map in-memory");
  return _store;
}

// ---------------------------------------------------------------------------
// API pública
// ---------------------------------------------------------------------------

const DEFAULT_TTL_MS = 60_000; // 60 segundos

/**
 * Guarda un challenge para un deviceId con TTL de 60s.
 */
export async function saveChallenge(
  deviceId: string,
  challenge: string,
  ttlMs: number = DEFAULT_TTL_MS,
): Promise<void> {
  const store = await getStore();
  await store.save(deviceId, challenge, ttlMs);
}

/**
 * Obtiene un challenge pendiente para un deviceId.
 * Devuelve null si no existe o si expiró.
 */
export async function getChallenge(
  deviceId: string,
): Promise<ChallengeEntry | null> {
  const store = await getStore();
  return store.get(deviceId);
}

/**
 * Elimina un challenge (one-time use — llamar tras verificar la firma).
 */
export async function deleteChallenge(deviceId: string): Promise<void> {
  const store = await getStore();
  await store.delete(deviceId);
}
