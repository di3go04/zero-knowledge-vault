import { describe, it, expect } from "vitest";
import { zeroBuffer, clearCryptoKeyRef, clearKeyPairRef } from "../memory-zero";

describe("zeroBuffer", () => {
  it("should clear an ArrayBuffer", () => {
    const buf = new Uint8Array([1, 2, 3, 4, 5]);
    const view = new Uint8Array(buf.buffer);
    zeroBuffer(buf.buffer);
    expect(Array.from(view)).toEqual([0, 0, 0, 0, 0]);
  });

  it("should clear a Uint8Array", () => {
    const arr = new Uint8Array([1, 2, 3]);
    zeroBuffer(arr);
    expect(Array.from(arr)).toEqual([0, 0, 0]);
  });

  it("should handle null input", () => {
    expect(() => zeroBuffer(null)).not.toThrow();
  });

  it("should handle undefined input", () => {
    expect(() => zeroBuffer(undefined)).not.toThrow();
  });

  it("should handle empty buffer", () => {
    const arr = new Uint8Array(0);
    expect(() => zeroBuffer(arr)).not.toThrow();
  });
});

describe("clearCryptoKeyRef", () => {
  it("should set ref to null", () => {
    const ref = { current: {} as CryptoKey };
    clearCryptoKeyRef(ref);
    expect(ref.current).toBeNull();
  });
});

describe("clearKeyPairRef", () => {
  it("should clear the key pair ref", () => {
    const ref = {
      current: {
        privateKey: {} as CryptoKey,
        publicKey: {} as CryptoKey,
      } as CryptoKeyPair,
    };
    clearKeyPairRef(ref);
    expect(ref.current).toBeNull();
  });

  it("should handle null current", () => {
    const ref = { current: null as unknown as CryptoKeyPair };
    clearKeyPairRef(ref);
    expect(ref.current).toBeNull();
  });
});
