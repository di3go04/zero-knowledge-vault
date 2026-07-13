/**
 * lru-cache.ts — Cache LRU para llaves públicas con TTL.
 *
 */

interface CacheEntry<V> {
  value: V;
  expiresAt: number;
}

export class LRUCache<K, V> {
  private map = new Map<K, CacheEntry<V>>();
  private maxEntries: number;
  private ttlMs: number;

  constructor(maxEntries: number = 50, ttlMs: number = 5 * 60 * 1000) {
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
  }

  get(key: K): V | null {
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key);
      return null;
    }
    // Mover al final (más reciente) — LRU
    this.map.delete(key);
    this.map.set(key, entry);
    return entry.value;
  }

  set(key: K, value: V): void {
    // Evictar el más antiguo si estamos al límite
    if (this.map.size >= this.maxEntries && !this.map.has(key)) {
      const firstKey = this.map.keys().next().value;
      if (firstKey !== undefined) this.map.delete(firstKey);
    }
    this.map.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  clear(): void {
    this.map.clear();
  }

  get size(): number {
    return this.map.size;
  }
}

// Cache global de llaves públicas por email
import { importPublicKeyJwk } from "./crypto-client";

const publicKeyCache = new LRUCache<string, CryptoKey>(50, 5 * 60 * 1000);

export async function getCachedPublicKey(
  email: string,
  fetchFn: () => Promise<JsonWebKey>,
): Promise<CryptoKey> {
  const cached = publicKeyCache.get(email);
  if (cached) return cached;

  const jwk = await fetchFn();
  const key = await importPublicKeyJwk(jwk);
  publicKeyCache.set(email, key);
  return key;
}
