export function setupOTel() {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return;

  console.log(`[otel] Tracing to ${endpoint}`);
}

export function traceRequest(method: string, path: string, durationMs: number, status: number) {
  const endpoint = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (!endpoint) return;

  fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      traceId: crypto.randomUUID(),
      spans: [{
        name: `${method} ${path}`,
        durationMs,
        status,
        attributes: { "http.method": method, "http.route": path, "http.status_code": status },
      }],
    }),
  }).catch(() => {});
}
