/**
 * =====================================================================
 * rate-limit.ts — Rate limiter in-memory para endpoints sensibles.
 * =====================================================================
 * Implementación simple con mapa IP+key → array de timestamps.
 * En producción se debería usar Redis o similar para compartir estado
 * entre instancias, pero para una demo single-process esto es suficiente.
 *
 * Política por defecto: 5 intentos por ventana de 15 minutos.
 * =====================================================================
 */

interface RateLimitEntry {
  attempts: number[]; // timestamps de cada intento
}

const store = new Map<string, RateLimitEntry>();

// Limpiar entradas expiradas cada 5 minutos para evitar memory leak
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;
let lastCleanup = Date.now();

function cleanupOldEntries(windowMs: number) {
  const now = Date.now();
  if (now - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = now;
  const cutoff = now - windowMs;
  for (const [key, entry] of store) {
    entry.attempts = entry.attempts.filter((t) => t > cutoff);
    if (entry.attempts.length === 0) {
      store.delete(key);
    }
  }
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number; // 0 si allowed=true
}

/**
 * Verifica si una acción está permitida bajo el rate limit.
 * Registra el intento actual (siempre, incluso si es denegado).
 *
 * @param key Clave compuesta (ej. `login:${ip}:${email}`).
 * @param maxAttempts Máximo de intentos por ventana.
 * @param windowMs Ventana en milisegundos.
 */
export function checkRateLimit(
  key: string,
  maxAttempts: number = 5,
  windowMs: number = 15 * 60 * 1000,
): RateLimitResult {
  cleanupOldEntries(windowMs);

  const now = Date.now();
  const cutoff = now - windowMs;

  let entry = store.get(key);
  if (!entry) {
    entry = { attempts: [] };
    store.set(key, entry);
  }

  // Filtrar intentos dentro de la ventana actual
  entry.attempts = entry.attempts.filter((t) => t > cutoff);

  if (entry.attempts.length >= maxAttempts) {
    // Calcular cuándo expira el intento más antiguo → retry-after
    const oldest = Math.min(...entry.attempts);
    const retryAfterMs = oldest + windowMs - now;
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    };
  }

  // Registrar el intento actual
  entry.attempts.push(now);

  return {
    allowed: true,
    remaining: maxAttempts - entry.attempts.length,
    retryAfterSeconds: 0,
  };
}

/**
 * Resetea el rate limit para una clave (ej. tras login exitoso).
 */
export function resetRateLimit(key: string): void {
  store.delete(key);
}
