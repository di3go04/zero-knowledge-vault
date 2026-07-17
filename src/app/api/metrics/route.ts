import { NextResponse } from "next/server";

const metrics = new Map<string, number>();

export function incrementMetric(name: string) {
  metrics.set(name, (metrics.get(name) || 0) + 1);
}

export function gaugeMetric(name: string, value: number) {
  metrics.set(name, value);
}

export function GET() {
  let output = "# HELP zk_vault_custom_metrics Custom metrics for Zero-Knowledge Vault\n";
  output += "# TYPE zk_vault_custom_metrics gauge\n\n";

  for (const [name, value] of metrics) {
    output += `zk_vault_${name} ${value}\n`;
  }

  output += `\n# HELP process_uptime_seconds Process uptime\n`;
  output += `# TYPE process_uptime_seconds gauge\n`;
  output += `process_uptime_seconds ${process.uptime()}\n`;

  output += `\n# HELP nodejs_heap_size_bytes Node.js heap size\n`;
  output += `# TYPE nodejs_heap_size_bytes gauge\n`;
  output += `nodejs_heap_size_bytes ${process.memoryUsage().heapUsed}\n`;

  return new NextResponse(output, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
