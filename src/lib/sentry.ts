export function initSentry() {
  if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
    console.warn("Sentry configured with DSN");
  }
}

export function captureError(error: Error, context?: Record<string, unknown>) {
  if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
    console.error("[Sentry]", error.message, context);
  } else {
    console.error(error);
  }
}
