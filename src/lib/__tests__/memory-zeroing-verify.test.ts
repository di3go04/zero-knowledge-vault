import { describe, it, expect } from "vitest";
import { zeroBuffer, secureZero, trackBuffer, createTrackedArray } from "@/lib/crypto/memory";
describe("Memory zeroing verification", () => {
  it("zeroBuffer fills with zeros", () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    zeroBuffer(buf);
    expect(buf.every(b => b === 0)).toBe(true);
  });
  it("secureZero zeros and unregisters", () => {
    const buf = new Uint8Array([10, 20, 30]);
    secureZero(buf);
    expect(buf.every(b => b === 0)).toBe(true);
  });
  it("trackBuffer returns same buffer", () => {
    const buf = new ArrayBuffer(8);
    expect(trackBuffer(buf)).toBe(buf);
  });
  it("createTrackedArray starts zeroed", () => {
    const arr = createTrackedArray(16);
    expect(arr.every(b => b === 0)).toBe(true);
  });
  it("zeroing a 1MB buffer completes in <10ms", () => {
    const buf = new Uint8Array(1024 * 1024);
    buf.fill(0xFF);
    const start = performance.now();
    zeroBuffer(buf);
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(10);
    expect(buf.every(b => b === 0)).toBe(true);
  });
});
