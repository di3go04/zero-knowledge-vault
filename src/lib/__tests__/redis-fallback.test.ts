import { describe, it, expect } from "vitest";
import { checkRateLimit, resetRateLimit } from "@/lib/rate-limit";
describe("Redis fallback → Map in-memory", () => {
  it("rate-limit works without Redis (Map fallback)", async () => {
    const key = `test:fallback:${Date.now()}`;
    const r1 = await checkRateLimit(key, 3, 60000);
    expect(r1.allowed).toBe(true);
    const r2 = await checkRateLimit(key, 3, 60000);
    expect(r2.allowed).toBe(true);
    const r3 = await checkRateLimit(key, 3, 60000);
    expect(r3.allowed).toBe(true);
    const r4 = await checkRateLimit(key, 3, 60000);
    expect(r4.allowed).toBe(false);
    await resetRateLimit(key);
  });
  it("fallback is consistent — same key returns same state", async () => {
    const key = `test:consistency:${Date.now()}`;
    await checkRateLimit(key, 5, 60000);
    await checkRateLimit(key, 5, 60000);
    const r3 = await checkRateLimit(key, 5, 60000);
    expect(r3.remaining).toBe(2);
    await resetRateLimit(key);
  });
});
