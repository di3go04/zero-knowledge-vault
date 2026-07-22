import * as Sentry from "@sentry/nextjs";
import { logger } from "./logger";

const hasDsn = !!(process.env.SENTRY_DSN || process.env.NEXT_PUBLIC_SENTRY_DSN);

export function captureException(error: unknown, context?: Record<string, unknown>): void {
  if (hasDsn) {
    Sentry.captureException(error, { extra: context });
  } else {
    logger.error({ err: error, context }, "[sentry fallback] no DSN configured");
  }
}

export function captureMessage(message: string, level: "info" | "warning" | "error" = "info", context?: Record<string, unknown>): void {
  if (hasDsn) {
    Sentry.captureMessage(message, { level, extra: context });
  } else {
    logger[level === "error" ? "error" : level === "warning" ? "warn" : "info"]({ context }, `[sentry fallback] ${message}`);
  }
}

export function setUser(user: { id: string; email?: string } | null): void {
  if (hasDsn) {
    Sentry.setUser(user ?? null);
  }
}

export function setTag(key: string, value: string): void {
  if (hasDsn) {
    Sentry.setTag(key, value);
  }
}

export function setExtra(key: string, value: unknown): void {
  if (hasDsn) {
    Sentry.setExtra(key, value);
  }
}

export function addBreadcrumb(breadcrumb: { message: string; category?: string; level?: "info" | "warning" | "error" }): void {
  if (hasDsn) {
    Sentry.addBreadcrumb(breadcrumb);
  }
}

export function startSpan<T>(name: string, fn: () => T): T {
  if (hasDsn) {
    return Sentry.startSpan({ name }, () => fn());
  }
  return fn();
}

export function wrapApiHandlerWithSentry<T extends (...args: unknown[]) => unknown>(handler: T, parameterizedRoute: string): T {
  if (hasDsn) {
    return Sentry.wrapApiHandlerWithSentry(handler, parameterizedRoute) as unknown as T;
  }
  return handler;
}

export { hasDsn };
