/**
 * API response caching — cache simple en memoria para GET requests.
 */
import { NextResponse } from "next/server";

const cache = new Map<string, { body: unknown; expiresAt: number }>();

export function getCached(key: string): unknown | null {
  const entry = cache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    cache.delete(key);
    return null;
  }
  return entry.body;
}

export function setCached(key: string, body: unknown, ttlMs: number = 30_000): void {
  cache.set(key, { body, expiresAt: Date.now() + ttlMs });
}

export function clearCache(prefix?: string): void {
  if (!prefix) { cache.clear(); return; }
  for (const key of cache.keys()) {
    if (key.startsWith(prefix)) cache.delete(key);
  }
}
