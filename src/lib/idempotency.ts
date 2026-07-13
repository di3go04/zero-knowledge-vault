/**
 * idempotency.ts — Idempotency keys para evitar duplicados en POST.
 *
 *
 * El cliente envía header `Idempotency-Key: <uuid>` en POST.
 * El servidor guarda la respuesta por 24h. Si la misma key llega
 * de nuevo, devuelve la respuesta cacheada en lugar de crear duplicado.
 */
import { NextResponse } from "next/server";

interface CachedResponse {
  status: number;
  body: unknown;
  expiresAt: number;
}

const cache = new Map<string, CachedResponse>();
const TTL_MS = 24 * 60 * 60 * 1000; // 24 horas

// Cleanup cada 5 minutos
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of cache) {
      if (entry.expiresAt <= now) cache.delete(key);
    }
  }, 5 * 60 * 1000).unref?.();
}

/**
 * Verifica si una petición con Idempotency-Key ya fue procesada.
 * Si fue procesada, devuelve la respuesta cacheada.
 * Si no, devuelve null (el handler debe proceder).
 */
export function checkIdempotency(key: string | null): NextResponse | null {
  if (!key) return null;
  const cached = cache.get(key);
  if (cached && cached.expiresAt > Date.now()) {
    return NextResponse.json(cached.body, { status: cached.status });
  }
  return null;
}

/**
 * Guarda la respuesta de una petición idempotente.
 */
export function saveIdempotentResponse(
  key: string | null,
  status: number,
  body: unknown,
): void {
  if (!key) return;
  cache.set(key, {
    status,
    body,
    expiresAt: Date.now() + TTL_MS,
  });
}
