import { describe, it, expect, beforeEach } from "vitest";
import { incrementRequestCount, getRequestCount, getMetrics } from "../metrics-store";
import { db } from "../db";

describe("MetricsStore", () => {
  beforeEach(async () => {
    await db.metric.deleteMany({ where: { name: "request_count" } }).catch(() => {});
  });

  it("incrementa request_count desde 0", async () => {
    const v = await incrementRequestCount();
    expect(v).toBeGreaterThanOrEqual(1);
  });

  it("incrementa acumulativamente", async () => {
    const v1 = await incrementRequestCount();
    const v2 = await incrementRequestCount();
    const v3 = await incrementRequestCount();
    expect(v3).toBeGreaterThan(v2);
    expect(v2).toBeGreaterThan(v1);
  });

  it("getRequestCount devuelve el valor actual", async () => {
    await incrementRequestCount();
    await incrementRequestCount();
    const count = await getRequestCount();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  it("getMetrics devuelve request_count y posiblemente active_connections", async () => {
    await incrementRequestCount();
    await incrementRequestCount();
    await incrementRequestCount();

    const metrics = await getMetrics();
    expect(metrics.request_count).toBeGreaterThanOrEqual(3);
    // active_connections puede ser null si no hay Redis — no debería fallar
    expect(metrics).toHaveProperty("request_count");
  });

  it("persiste en DB (no es variable en memoria)", async () => {
    await incrementRequestCount();

    const fromDb = await db.metric.findUnique({ where: { name: "request_count" } });
    expect(fromDb).not.toBeNull();
    expect(fromDb!.value).toBeGreaterThanOrEqual(1);
  });
});
