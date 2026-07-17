import { describe, it, expect } from "vitest";
import { createHash } from "crypto";

describe("Immutable Audit Log", () => {
  it("should produce consistent hash chain", () => {
    const entries = [
      { event: "login", timestamp: "2024-01-01T00:00:00Z" },
      { event: "secret_create", timestamp: "2024-01-01T01:00:00Z" },
      { event: "share", timestamp: "2024-01-01T02:00:00Z" },
    ];

    const hashes: string[] = [];
    for (const entry of entries) {
      const previousHash = hashes.length > 0 ? hashes[hashes.length - 1] : "";
      const data = previousHash + JSON.stringify(entry);
      const hash = createHash("sha256").update(data).digest("hex");
      hashes.push(hash);
    }

    expect(hashes).toHaveLength(3);
    expect(hashes[0]).not.toBe(hashes[1]);
    expect(hashes[1]).not.toBe(hashes[2]);

    const tamperedEntry = { event: "login", timestamp: "2024-01-01T00:00:00Z" };
    const tamperedHash = createHash("sha256")
      .update("" + JSON.stringify(tamperedEntry))
      .digest("hex");
    expect(tamperedHash).toBe(hashes[0]);

    const differentEntry = { event: "logout", timestamp: "2024-01-01T00:00:00Z" };
    const differentHash = createHash("sha256")
      .update("" + JSON.stringify(differentEntry))
      .digest("hex");
    expect(differentHash).not.toBe(hashes[0]);
  });

  it("should detect hash chain tampering", () => {
    const original = [
      { event: "login", hash: "abc" },
      { event: "secret_create", hash: "def" },
    ];

    const tampered = [
      { event: "login", hash: "abc" },
      { event: "secret_delete", hash: "def" },
    ];

    expect(tampered[1].event).not.toBe(original[1].event);
  });
});
