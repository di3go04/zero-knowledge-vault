/**
 * system-metrics.ts — Métricas del sistema (uptime, memoria, requests).
 */
const startTime = Date.now();
let requestCount = 0;
let errorCount = 0;
const responseTimes: number[] = [];

export function recordRequest(durationMs: number, isError: boolean = false): void {
  requestCount++;
  if (isError) errorCount++;
  responseTimes.push(durationMs);
  if (responseTimes.length > 1000) responseTimes.shift();
}

export function getSystemMetrics() {
  const uptimeMs = Date.now() - startTime;
  const memUsage = process.memoryUsage();
  const avgResponseTime = responseTimes.length > 0
    ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
    : 0;
  const p95ResponseTime = responseTimes.length > 0
    ? responseTimes.sort((a, b) => a - b)[Math.floor(responseTimes.length * 0.95)]
    : 0;
  const errorRate = requestCount > 0 ? (errorCount / requestCount) * 100 : 0;

  return {
    uptime: {
      seconds: Math.floor(uptimeMs / 1000),
      human: `${Math.floor(uptimeMs / 86400000)}d ${Math.floor((uptimeMs % 86400000) / 3600000)}h ${Math.floor((uptimeMs % 3600000) / 60000)}m`,
    },
    memory: {
      rss: Math.round(memUsage.rss / 1024 / 1024),
      heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
      heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
      external: Math.round(memUsage.external / 1024 / 1024),
    },
    requests: {
      total: requestCount,
      errors: errorCount,
      errorRate: Math.round(errorRate * 100) / 100,
    },
    responseTime: {
      avg: Math.round(avgResponseTime * 100) / 100,
      p95: Math.round(p95ResponseTime * 100) / 100,
    },
  };
}
