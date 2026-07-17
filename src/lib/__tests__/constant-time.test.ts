import { describe, it, expect } from "vitest";
import { timingSafeEqual, timingSafeBufferEqual, constantTimeCompare } from "../constant-time";

describe("timingSafeEqual", () => {
  it("should return true for equal strings", () => {
    expect(timingSafeEqual("hello", "hello")).toBe(true);
  });

  it("should return false for different strings", () => {
    expect(timingSafeEqual("hello", "world")).toBe(false);
  });

  it("should return false for different length strings", () => {
    expect(timingSafeEqual("hello", "hello!")).toBe(false);
  });

  it("should return true for empty strings", () => {
    expect(timingSafeEqual("", "")).toBe(true);
  });
});

describe("timingSafeBufferEqual", () => {
  it("should return true for equal buffers", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    expect(timingSafeBufferEqual(a, b)).toBe(true);
  });

  it("should return false for different buffers", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 4]);
    expect(timingSafeBufferEqual(a, b)).toBe(false);
  });

  it("should return false for different length buffers", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(timingSafeBufferEqual(a, b)).toBe(false);
  });

  it("should return true for empty buffers", () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array(0);
    expect(timingSafeBufferEqual(a, b)).toBe(true);
  });
});

describe("constantTimeCompare", () => {
  it("should return true for equal strings", () => {
    expect(constantTimeCompare("test", "test")).toBe(true);
  });

  it("should return false for different strings", () => {
    expect(constantTimeCompare("abc", "xyz")).toBe(false);
  });

  it("should return false for different length strings", () => {
    expect(constantTimeCompare("short", "longer")).toBe(false);
  });

  it("should return true for empty strings", () => {
    expect(constantTimeCompare("", "")).toBe(true);
  });
});
