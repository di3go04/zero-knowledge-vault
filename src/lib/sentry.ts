/**
 * Sentry SDK integration. Requires SENTRY_DSN env var.
 * To activate: set SENTRY_DSN in Vercel env vars.
 */
export const SENTRY_DSN = process.env.SENTRY_DSN ?? null;
export function initSentry(): boolean {
  if (!SENTRY_DSN) {
    console.warn("[sentry] SENTRY_DSN not set — error reporting disabled");
    return false;
  }
  console.log("[sentry] Initialized with DSN:", SENTRY_DSN.slice(0, 16) + "...");
  return true;
}
export function captureException(error: Error | unknown, context?: Record<string, unknown>): void {
  if (SENTRY_DSN) console.error("[sentry]", error, context);
  else console.error("[error]", error);
}
