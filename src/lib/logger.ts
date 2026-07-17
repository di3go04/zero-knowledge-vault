/**
 * logger.ts — Structured logging via pino.
 *
 * Pino is the fastest Node.js logger and produces JSON output by default,
 * which is consumed by most log aggregators (Loki, Datadog, CloudWatch,
 * Elastic, etc.). In development, we use pino-pretty for human-readable
 * output.
 */
import pino from "pino";

const isDev = process.env.NODE_ENV !== "production";
const level = process.env.LOG_LEVEL ?? (isDev ? "debug" : "info");

export const logger = pino({
  level,
  base: {
    service: "zk-vault",
    version: process.env.npm_package_version ?? "1.0.0",
  },
  redact: {
    paths: [
      "masterPassword",
      "masterKey",
      "privateKey",
      "privateKeyJwk",
      "encryptedPrivateKeyJwk",
      "sessionToken",
      "token",
      "password",
      "secret",
      "apiKey",
      "authorization",
      "req.headers.authorization",
      "req.headers.cookie",
    ],
    censor: "[REDACTED]",
  },
  transport: isDev
    ? {
        target: "pino-pretty",
        options: {
          colorize: true,
          translateTime: "SYS:standard",
          ignore: "pid,hostname",
        },
      }
    : undefined,
});

/**
 * Helper to create a child logger with additional context (e.g. requestId,
 * userId). Use this inside API routes:
 *
 *   const log = logger.child({ requestId, userId });
 *   log.info({ secretId }, "secret created");
 */
export function createLogger(bindings: Record<string, unknown>) {
  return logger.child(bindings);
}
