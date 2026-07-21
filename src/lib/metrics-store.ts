let requestCount = 0;
let errorCount = 0;
const startTime = Date.now();
export function recordRequest(): void { requestCount++; }
export function recordError(): void { errorCount++; }
export function getMetrics(): string {
  const uptime = (Date.now() - startTime) / 1000;
  return [
    "# HELP zk_vault_requests_total Total requests",
    "# TYPE zk_vault_requests_total counter",
    `zk_vault_requests_total ${requestCount}`,
    "# HELP zk_vault_errors_total Total errors",
    "# TYPE zk_vault_errors_total counter",
    `zk_vault_errors_total ${errorCount}`,
    "# HELP zk_vault_uptime_seconds Uptime in seconds",
    "# TYPE zk_vault_uptime_seconds gauge",
    `zk_vault_uptime_seconds ${uptime}`,
    "# HELP zk_vault_memory_heap_used_bytes Heap memory used",
    "# TYPE zk_vault_memory_heap_used_bytes gauge",
    `zk_vault_memory_heap_used_bytes ${process.memoryUsage().heapUsed}`,
    "# HELP zk_vault_active_connections Active connections",
    "# TYPE zk_vault_active_connections gauge",
    "zk_vault_active_connections 1",
  ].join("\n");
}
