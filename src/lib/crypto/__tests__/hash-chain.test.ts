/**
 * Tests for hash-chain.ts (tamper-evident audit log chain).
 */
import { describe, it, expect } from "vitest";
import { sha256Hex, computeLogHash, verifyChain } from "../hash-chain";

describe("sha256Hex", () => {
  it("produces a 64-char hex string for non-empty input", async () => {
    const hash = await sha256Hex("test");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for the same input", async () => {
    const a = await sha256Hex("same-input");
    const b = await sha256Hex("same-input");
    expect(a).toBe(b);
  });

  it("differs for different inputs", async () => {
    const a = await sha256Hex("input-A");
    const b = await sha256Hex("input-B");
    expect(a).not.toBe(b);
  });

  it("matches the known SHA-256 of empty string", async () => {
    const hash = await sha256Hex("");
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    expect(hash).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});

describe("computeLogHash", () => {
  it("produces a 64-char hex hash", async () => {
    const hash = await computeLogHash({
      prevHash: null,
      encryptedEvent: "event-blob",
      eventIv: "iv-blob",
      createdAt: "2025-01-01T00:00:00.000Z",
    });
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces different hashes for different prevHash", async () => {
    const a = await computeLogHash({
      prevHash: null,
      encryptedEvent: "event",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    });
    const b = await computeLogHash({
      prevHash: "some-previous-hash",
      encryptedEvent: "event",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    });
    expect(a).not.toBe(b);
  });

  it("produces different hashes for different encryptedEvent", async () => {
    const a = await computeLogHash({
      prevHash: null,
      encryptedEvent: "event-A",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    });
    const b = await computeLogHash({
      prevHash: null,
      encryptedEvent: "event-B",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    });
    expect(a).not.toBe(b);
  });

  it("produces different hashes for different createdAt", async () => {
    const a = await computeLogHash({
      prevHash: null,
      encryptedEvent: "event",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    });
    const b = await computeLogHash({
      prevHash: null,
      encryptedEvent: "event",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:01.000Z",
    });
    expect(a).not.toBe(b);
  });
});

describe("verifyChain", () => {
  it("returns ok=true for a valid chain of 3 entries", async () => {
    // Build a chain manually
    const entries: Array<{
      prevHash: string | null;
      logHash: string | null;
      encryptedEvent: string;
      eventIv: string;
      createdAt: string;
    }> = [];

    let prevHash: string | null = null;
    for (let i = 0; i < 3; i++) {
      const entry = {
        encryptedEvent: `event-${i}`,
        eventIv: `iv-${i}`,
        createdAt: `2025-01-0${i + 1}T00:00:00.000Z`,
      };
      const logHash = await computeLogHash({ prevHash, ...entry });
      entries.push({ prevHash, logHash, ...entry });
      prevHash = logHash;
    }

    const result = await verifyChain(entries);
    expect(result.ok).toBe(true);
    expect(result.firstBrokenIndex).toBeNull();
  });

  it("returns ok=true for an empty chain", async () => {
    const result = await verifyChain([]);
    expect(result.ok).toBe(true);
    expect(result.firstBrokenIndex).toBeNull();
  });

  it("returns ok=true for a single-entry chain with null prevHash", async () => {
    const entry = {
      prevHash: null,
      encryptedEvent: "event",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    };
    const logHash = await computeLogHash(entry);
    const result = await verifyChain([{ ...entry, logHash }]);
    expect(result.ok).toBe(true);
  });

  it("detects when an entry's prevHash doesn't match the previous logHash", async () => {
    // Build a chain
    const entries: Array<{ prevHash: string | null; logHash: string | null; encryptedEvent: string; eventIv: string; createdAt: string }> = [];
    let prevHash: string | null = null;
    for (let i = 0; i < 3; i++) {
      const entry = {
        encryptedEvent: `event-${i}`,
        eventIv: `iv-${i}`,
        createdAt: `2025-01-0${i + 1}T00:00:00.000Z`,
      };
      const logHash = await computeLogHash({ prevHash, ...entry });
      entries.push({ prevHash, logHash, ...entry });
      prevHash = logHash;
    }

    // Tamper: change the prevHash of the 3rd entry to a wrong value
    entries[2].prevHash = "tampered-prev-hash";

    const result = await verifyChain(entries);
    expect(result.ok).toBe(false);
    expect(result.firstBrokenIndex).toBe(2);
  });

  it("detects when an entry's logHash was recomputed with tampered data", async () => {
    // Build a chain
    const entries: Array<{ prevHash: string | null; logHash: string | null; encryptedEvent: string; eventIv: string; createdAt: string }> = [];
    let prevHash: string | null = null;
    for (let i = 0; i < 3; i++) {
      const entry = {
        encryptedEvent: `event-${i}`,
        eventIv: `iv-${i}`,
        createdAt: `2025-01-0${i + 1}T00:00:00.000Z`,
      };
      const logHash = await computeLogHash({ prevHash, ...entry });
      entries.push({ prevHash, logHash, ...entry });
      prevHash = logHash;
    }

    // Tamper: change the encryptedEvent of the 2nd entry WITHOUT
    // recomputing its logHash. The stored logHash no longer matches.
    entries[1].encryptedEvent = "tampered-event";

    const result = await verifyChain(entries);
    expect(result.ok).toBe(false);
    expect(result.firstBrokenIndex).toBe(1);
  });

  it("detects when the first entry's prevHash is not null", async () => {
    const entry = {
      prevHash: "should-be-null",
      encryptedEvent: "event",
      eventIv: "iv",
      createdAt: "2025-01-01T00:00:00.000Z",
    };
    const logHash = await computeLogHash(entry);
    const result = await verifyChain([{ ...entry, logHash }]);
    expect(result.ok).toBe(false);
    expect(result.firstBrokenIndex).toBe(0);
  });
});
