/**
 * db-pool-config.ts — Configuración de connection pooling para Prisma.
 */
export const DB_POOL_CONFIG = {
  // SQLite no soporta pooling real, pero para PostgreSQL en producción:
  // connectionLimit: 10,
  // poolTimeout: 20,
  // Se configura via DATABASE_URL con parámetros:
  // ?connection_limit=10&pool_timeout=20
  log: process.env.NODE_ENV === "development" ? ["query", "error", "warn"] : ["error"],
  errorFormat: "minimal" as const,
};

export const QUERY_TIMEOUT_MS = 10_000; // 10 segundos
export const TRANSACTION_TIMEOUT_MS = 30_000; // 30 segundos
