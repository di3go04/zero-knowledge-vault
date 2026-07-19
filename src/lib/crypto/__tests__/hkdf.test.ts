/**
 * Tests for HKDF subkey derivation (src/lib/crypto/hkdf.ts).
 *
 * These tests use the real Web Crypto API (available in Node.js 18+
 * via the `globalThis.crypto` global). No mocks, no `btoa` hacks.
 */
import { describe, it, expect } from "vitest";
import {
  deriveSubKey,
  deriveAllSubKeys,
  deriveRawBytes,
  type SubKeyType,
} from "../hkdf";

async function makeMasterKey(): Promise<CryptoKey> {
  // Import the master key as HKDF-compatible (AES-GCM keys can be used
  // with deriveKey/deriveBits in Web Crypto, but some implementations
  // reject deriveBits on AES keys — so we import as HKDF directly).
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HKDF" },
    false,
    ["deriveKey", "deriveBits"]
  );
}

describe("deriveSubKey", () => {
  it("derives a non-extractable AES-GCM key from the master key", async () => {
    const master = await makeMasterKey();
    const sub = await deriveSubKey(master, "audit");

    expect(sub).toBeInstanceOf(CryptoKey);
    expect(sub.algorithm.name).toBe("AES-GCM");
    expect(sub.extractable).toBe(false);
    expect(sub.usages).toContain("encrypt");
    expect(sub.usages).toContain("decrypt");
  });

  it("derives DIFFERENT keys for different purposes", async () => {
    const master = await makeMasterKey();
    const audit = await deriveSubKey(master, "audit");
    const device = await deriveSubKey(master, "device");
    const share = await deriveSubKey(master, "share");
    const metadata = await deriveSubKey(master, "metadata");

    // Export raw to compare bytes
    const auditRaw = await crypto.subtle.exportKey("raw", audit).catch(() => null);
    const deviceRaw = await crypto.subtle.exportKey("raw", device).catch(() => null);

    // Both should be non-exportable, so export should fail (return null)
    expect(auditRaw).toBeNull();
    expect(deviceRaw).toBeNull();

    // But they should still be different keys — verify by encrypting
    // the same plaintext with each and checking the ciphertexts differ.
    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("test");

    const encAudit = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      audit,
      plaintext
    );
    const iv2 = new Uint8Array(12);
    const encDevice = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv2 },
      device,
      plaintext
    );

    // Different keys → different ciphertexts (extremely high probability)
    expect(new Uint8Array(encAudit)).not.toEqual(new Uint8Array(encDevice));
  });

  it("derives the SAME key for the same purpose from the same master", async () => {
    const master = await makeMasterKey();
    const a1 = await deriveSubKey(master, "audit");
    const a2 = await deriveSubKey(master, "audit");

    // Encrypt same plaintext with same IV — should produce same ciphertext
    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("test");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a2, plaintext);
    expect(new Uint8Array(c1)).toEqual(new Uint8Array(c2));
  });

  it("derives DIFFERENT keys from DIFFERENT master keys", async () => {
    const m1 = await makeMasterKey();
    const m2 = await makeMasterKey();
    const a1 = await deriveSubKey(m1, "audit");
    const a2 = await deriveSubKey(m2, "audit");

    const iv = new Uint8Array(12);
    const plaintext = new TextEncoder().encode("test");
    const c1 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a1, plaintext);
    const c2 = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, a2, plaintext);
    expect(new Uint8Array(c1)).not.toEqual(new Uint8Array(c2));
  });
});

describe("deriveAllSubKeys", () => {
  it("returns all four subkeys at once", async () => {
    const master = await makeMasterKey();
    const all = await deriveAllSubKeys(master);

    const keys: SubKeyType[] = ["audit", "device", "share", "metadata"];
    for (const k of keys) {
      expect(all[k]).toBeInstanceOf(CryptoKey);
      expect(all[k].algorithm.name).toBe("AES-GCM");
    }
  });
});

describe("deriveRawBytes", () => {
  it("derives the requested number of bytes", async () => {
    const master = await makeMasterKey();
    const bytes = await deriveRawBytes(master, "test-info-1", 32);
    expect(bytes.byteLength).toBe(32);
  });

  it("derives DIFFERENT bytes for different info strings", async () => {
    const master = await makeMasterKey();
    const a = await deriveRawBytes(master, "info-A", 32);
    const b = await deriveRawBytes(master, "info-B", 32);
    expect(new Uint8Array(a)).not.toEqual(new Uint8Array(b));
  });
});
