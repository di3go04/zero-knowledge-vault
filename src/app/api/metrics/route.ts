/**
 * GET /api/metrics — Prometheus metrics endpoint.
 *
 */
import { NextResponse } from "next/server";

// In-memory metrics counters
const metrics = {
  requests_total: 0,
  auth_login_total: 0,
  auth_login_failed_total: 0,
  secrets_created_total: 0,
  secrets_shared_total: 0,
  devices_enrolled_total: 0,
  rate_limited_total: 0,
};

export function incrementMetric(name: keyof typeof metrics) {
  metrics[name]++;
}

export async function GET() {
  const lines = Object.entries(metrics).map(
    ([key, value]) => `zk_vault_${key} ${value}`,
  );
  lines.unshift("# TYPE zk_vault_requests_total counter");

  return NextResponse.json(
    { metrics },
    { headers: { "Content-Type": "application/json" } },
  );
}
