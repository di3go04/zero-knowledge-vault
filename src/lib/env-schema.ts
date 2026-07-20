/**
 * BLOQUE 1 — Arranque seguro: validación centralizada de variables de
 * entorno críticas. Cualquier variable obligatoria que falte aborta el
 * proceso con exit(1) en lugar de usar fallbacks hardcodeados.
 *
 * Esta validación se ejecuta al importar el módulo (side-effect) y solo
 * se aplica cuando NODE_ENV !== "test" (para no romper vitest).
 *
 * Variables críticas:
 *   - DATABASE_URL:        string, no vacío
 *   - SESSION_SECRET:      string, mínimo 32 chars, no placeholder
 *
 * Variables opcionales:
 *   - REDIS_URL:           string, URL Redis (para rate limit + blacklist)
 *   - DECOY_HMAC_KEY:      string, clave HMAC decoy login
 *   - LOG_LEVEL:           "debug" | "info" | "warn" | "error"
 *   - NODE_ENV:            "development" | "production" | "test"
 */
type LogLevel = "debug" | "info" | "warn" | "error";
type NodeEnv = "development" | "production" | "test";

interface EnvSchema {
  DATABASE_URL: string;
  SESSION_SECRET: string;
  REDIS_URL?: string;
  DECOY_HMAC_KEY?: string;
  LOG_LEVEL: LogLevel;
  NODE_ENV: NodeEnv;
}

const PLACEHOLDER_PATTERNS = [
  "change-me",
  "change-in-prod",
  "your-",
  "xxx",
  "placeholder",
];

function isPlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return PLACEHOLDER_PATTERNS.some((p) => lower.includes(p));
}

function validateEnv(): EnvSchema {
  const isTest =
    process.env.NODE_ENV === "test" || process.env.VITEST === "true";

  const errors: string[] = [];

  // NODE_ENV
  const nodeEnv = (process.env.NODE_ENV ?? "development") as NodeEnv;
  if (!["development", "production", "test"].includes(nodeEnv)) {
    errors.push(`NODE_ENV inválido: "${nodeEnv}". Debe ser development|production|test.`);
  }

  // LOG_LEVEL
  const logLevel = (process.env.LOG_LEVEL ??
    (nodeEnv === "production" ? "info" : "debug")) as LogLevel;
  if (!["debug", "info", "warn", "error"].includes(logLevel)) {
    errors.push(`LOG_LEVEL inválido: "${logLevel}".`);
  }

  // En test, permitir valores por defecto para no romper vitest.
  if (isTest) {
    return {
      DATABASE_URL: process.env.DATABASE_URL ?? "file:./db/test.db",
      SESSION_SECRET:
        process.env.SESSION_SECRET ??
        "test-only-secret-do-not-use-in-production-min-32-chars!!",
      REDIS_URL: process.env.REDIS_URL,
      DECOY_HMAC_KEY: process.env.DECOY_HMAC_KEY,
      LOG_LEVEL: logLevel,
      NODE_ENV: "test",
    };
  }

  // DATABASE_URL (obligatorio)
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    errors.push(
      "DATABASE_URL no está configurado. " +
        "Ejemplo: file:./db/dev.db (SQLite) o postgresql://user:pass@host:5432/db (PostgreSQL)",
    );
  }

  // SESSION_SECRET (obligatorio, mínimo 32 chars, no placeholder)
  const sessionSecret = process.env.SESSION_SECRET;
  if (!sessionSecret) {
    errors.push(
      "SESSION_SECRET no está configurado. " +
        "Genera uno con: openssl rand -base64 48",
    );
  } else if (sessionSecret.length < 32) {
    errors.push(
      `SESSION_SECRET demasiado corto (${sessionSecret.length} chars, mínimo 32). ` +
        "Genera uno nuevo con: openssl rand -base64 48",
    );
  } else if (isPlaceholder(sessionSecret)) {
    errors.push(
      "SESSION_SECRET contiene un placeholder. " +
        "NO uses valores de ejemplo en producción.",
    );
  }

  // En producción, SESSION_SECRET debe ser criptográficamente aleatorio.
  if (nodeEnv === "production" && sessionSecret) {
    if (sessionSecret === "dev-only-secret-min-32-chars-do-not-use-in-production!!") {
      errors.push(
        "SESSION_SECRET es el valor de desarrollo. NO uses este valor en producción.",
      );
    }
  }

  if (errors.length > 0) {
    console.error("\n[FATAL] Variables de entorno inválidas:\n");
    for (const e of errors) console.error("  - " + e);
    console.error(
      "\nConsulta .env.example para ver los valores esperados.\n" +
        "Genera secretos con: openssl rand -base64 48\n",
    );
    process.exit(1);
  }

  return {
    DATABASE_URL: databaseUrl!,
    SESSION_SECRET: sessionSecret!,
    REDIS_URL: process.env.REDIS_URL,
    DECOY_HMAC_KEY: process.env.DECOY_HMAC_KEY,
    LOG_LEVEL: logLevel,
    NODE_ENV: nodeEnv,
  };
}

export const env = validateEnv();

/**
 * Helper para validar en runtime que una variable opcional esté presente
 * antes de usarla. Lanza error explícito si falta.
 */
export function requireEnv(name: keyof EnvSchema): string {
  const value = env[name];
  if (!value) {
    throw new Error(
      `Variable de entorno ${name} requerida pero no configurada.`,
    );
  }
  return value;
}
