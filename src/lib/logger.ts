import pino from "pino";
import { captureError } from "./sentry";

const isProduction = process.env.NODE_ENV === "production";

export const logger = pino({
  level: isProduction ? "info" : "debug",
  transport: isProduction
    ? undefined
    : {
        target: "pino/file",
        options: { destination: 1 },
      },
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

export function createRequestLogger() {
  const start = Date.now();
  const requestId = crypto.randomUUID?.() ?? Math.random().toString(36);

  return {
    requestId,
    info: (msg: string, data?: Record<string, unknown>) => {
      logger.info({ requestId, ...data }, msg);
    },
    error: (msg: string, data?: Record<string, unknown>) => {
      logger.error({ requestId, ...data }, msg);
      captureError(new Error(msg), { requestId, ...data });
    },
    done: (status: number) => {
      const duration = Date.now() - start;
      logger.info({ requestId, status, durationMs: duration }, "request completed");
    },
  };
}
