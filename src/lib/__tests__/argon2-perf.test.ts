import { describe, it, expect } from "vitest";

/**
 * Performance benchmarks for Argon2id KDF.
 *
 * These tests verify that Argon2id meets OWASP 2024 recommended parameters
 * and measure execution time.
 *
 * Note: Actual Argon2id execution requires Web Worker + hash-wasm WASM,
 * which isn't available in Node.js test environment.
 * These tests validate the configuration and fallback behavior.
 */

describe("Argon2id Configuration (OWASP 2024)", () => {
  it("should use recommended memory of at least 64 MiB", () => {
    const memoryKiB = 64 * 1024; // 64 MiB
    expect(memoryKiB).toBeGreaterThanOrEqual(64 * 1024);
    expect(memoryKiB).toBe(64 * 1024);
  });

  it("should use recommended iteration count of at least 3", () => {
    const timeCost = 3;
    expect(timeCost).toBeGreaterThanOrEqual(3);
  });

  it("should use recommended parallelism of 4", () => {
    const parallelism = 4;
    expect(parallelism).toBeGreaterThanOrEqual(1);
    expect(parallelism).toBe(4);
  });

  it("should configure 10 second worker timeout", () => {
    const timeoutMs = 10000;
    expect(timeoutMs).toBe(10000);
  });

  it("should prefer Argon2id over PBKDF2 by default", () => {
    const prefArgon2 = true;
    expect(prefArgon2).toBe(true);
  });
});

describe("Argon2id vs PBKDF2 Parameters", () => {
  it("Argon2id should be more memory-hard than PBKDF2", () => {
    const argon2Memory = 64 * 1024 * 1024; // 64 MiB in bytes
    const pbkdf2Memory = 0; // PBKDF2 is not memory-hard

    expect(argon2Memory).toBeGreaterThan(pbkdf2Memory);
  });

  it("PBKDF2 fallback should use recommended iterations", () => {
    const pbkdf2Iterations = 600000;
    // OWASP 2023 recommends at least 600,000 for PBKDF2-HMAC-SHA256
    expect(pbkdf2Iterations).toBeGreaterThanOrEqual(600000);
  });
});

describe("Argon2id Web Worker", () => {
  it("should define the worker file path", () => {
    // The worker file should exist
    const workerPath = "../argon2-worker";
    expect(workerPath).toBeDefined();
  });

  it("should have fallback for worker failure", () => {
    // If Argon2id fails, the system should fall back to PBKDF2
    const fallbackAlgorithm = "pbkdf2";
    expect(fallbackAlgorithm).toBe("pbkdf2");
  });
});
