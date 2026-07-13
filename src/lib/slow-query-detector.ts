/**
 * slow-query-detector.ts — Detecta queries lentas y las loguea.
 */
import { logger } from "./logger";

const SLOW_QUERY_THRESHOLD_MS = 500;

const queryTimes: Map<string, number[]> = new Map();

export function recordQueryTime(query: string, durationMs: number): void {
  if (durationMs > SLOW_QUERY_THRESHOLD_MS) {
    logger.warn("Slow query detected", {
      durationMs,
      query: query.slice(0, 200),
      threshold: SLOW_QUERY_THRESHOLD_MS,
    });
  }

  // Acumular estadísticas
  const key = query.slice(0, 100);
  const times = queryTimes.get(key) ?? [];
  times.push(durationMs);
  if (times.length > 100) times.shift();
  queryTimes.set(key, times);
}

export function getSlowQueries(): Array<{ query: string; avgMs: number; maxMs: number; count: number }> {
  const result: Array<{ query: string; avgMs: number; maxMs: number; count: number }> = [];
  for (const [query, times] of queryTimes) {
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const max = Math.max(...times);
    if (avg > SLOW_QUERY_THRESHOLD_MS) {
      result.push({ query, avgMs: Math.round(avg), maxMs: Math.round(max), count: times.length });
    }
  }
  return result.sort((a, b) => b.avgMs - a.avgMs);
}
