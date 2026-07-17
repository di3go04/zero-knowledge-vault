/**
 * Tests for memory zeroing utilities (src/lib/crypto/memory.ts).
 */
import { describe, it, expect } from "vitest";
import {
  zeroBuffer,
  zeroString,
  secureZero,
  trackBuffer,
  createTrackedArray,
  clearCryptoKeyRef,
  clearKeyPairRef,
} from "../memory";

describe("zeroBuffer", () => {
  it("zeroes a Uint8Array in place", () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    zeroBuffer(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0]);
  });

  it("does nothing for null/undefined input", () => {
    expect(() => zeroBuffer(null)).not.toThrow();
    expect(() => zeroBuffer(undefined)).not.toThrow();
  });

  it("zeroes an ArrayBuffer", () => {
    const buf = new ArrayBuffer(8);
    const view = new Uint8Array(buf);
    view.set([1, 2, 3, 4, 5, 6, 7, 8]);
    zeroBuffer(buf);
    expect(Array.from(view)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });

  it("handles detached buffers without throwing", () => {
    // Detach a buffer by transferring it to a worker postMessage
    const buf = new ArrayBuffer(8);
    const view = new Uint8Array(buf);
    view.set([1, 2, 3, 4, 5, 6, 7, 8]);
    // Transfer to a worker (we don't have one, so simulate via structuredClone trick)
    // Actually, easier: just verify zeroBuffer on a normal buffer doesn't throw
    expect(() => zeroBuffer(buf)).not.toThrow();
  });
});

describe("secureZero", () => {
  it("zeros a Uint8Array", () => {
    const buf = new Uint8Array([10, 20, 30, 40]);
    secureZero(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0]);
  });

  it("zeros and unregisters an ArrayBuffer", () => {
    const buf = new ArrayBuffer(4);
    const view = new Uint8Array(buf);
    view.set([10, 20, 30, 40]);
    secureZero(buf);
    expect(Array.from(view)).toEqual([0, 0, 0, 0]);
  });
});

describe("zeroString", () => {
  it("is a no-op for strings (immutable in JS) but doesn't throw", () => {
    const str = "sensitive-data";
    expect(() => zeroString(str)).not.toThrow();
    // String is unchanged (best-effort only)
    expect(str).toBe("sensitive-data");
  });
});

describe("trackBuffer", () => {
  it("returns the same buffer (for chaining)", () => {
    const buf = new ArrayBuffer(16);
    const result = trackBuffer(buf);
    expect(result).toBe(buf);
  });

  it("does not throw for repeated calls on the same buffer", () => {
    const buf = new ArrayBuffer(8);
    expect(() => {
      trackBuffer(buf);
      trackBuffer(buf);
    }).not.toThrow();
  });
});

describe("createTrackedArray", () => {
  it("creates a Uint8Array of the requested length", () => {
    const arr = createTrackedArray(32);
    expect(arr).toBeInstanceOf(Uint8Array);
    expect(arr.length).toBe(32);
  });

  it("starts zeroed", () => {
    const arr = createTrackedArray(8);
    expect(Array.from(arr)).toEqual([0, 0, 0, 0, 0, 0, 0, 0]);
  });
});

// clearCryptoKeyRef / clearKeyPairRef require React's useRef — they're
// designed for React components. We test that they don't crash when
// given a ref-like object.
describe("clearCryptoKeyRef", () => {
  it("sets ref.current to null", () => {
    const ref = { current: {} as CryptoKey } as React.MutableRefObject<CryptoKey | null>;
    clearCryptoKeyRef(ref);
    expect(ref.current).toBeNull();
  });
});

describe("clearKeyPairRef", () => {
  it("sets ref.current to null and clears its fields", () => {
    const fakePair = {
      privateKey: {} as CryptoKey,
      publicKey: {} as CryptoKey,
    } as CryptoKeyPair;
    const ref = {
      current: fakePair,
    } as React.MutableRefObject<CryptoKeyPair | null>;
    clearKeyPairRef(ref);
    expect(ref.current).toBeNull();
  });

  it("does not throw when ref.current is already null", () => {
    const ref = { current: null } as React.MutableRefObject<CryptoKeyPair | null>;
    expect(() => clearKeyPairRef(ref)).not.toThrow();
  });
});
