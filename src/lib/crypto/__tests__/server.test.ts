/**
 * Tests for server-side crypto verification (src/lib/crypto/server.ts).
 *
 * These tests run in Node.js (no browser). They use the global Web Crypto
 * API (available in Node 18+) plus `node:crypto` for HMAC-based decoy
 * generation.
 */
import { describe, it, expect, beforeAll } from "vitest";
import {
  base64ToBytes,
  bytesToBase64,
  isValidBase64,
  validateKdfIterations,
  validateBase64Blob,
  canonicalJwkString,
  publicKeyFingerprint,
  buildPopMessage,
  verifyPopSignature,
  generateDecoyLoginResponse,
  verifyChallenge,
} from "../server";
import {
  generateRsaKeyPair,
  exportPublicKeyJwk,
  signPop,
  randomBytes,
  bufToBase64,
  generateEcdhKeyPair,
  exportEcdhPublicKeyJwk,
  importEcdhPublicKeyForVerifying,
  importEcdhPrivateKeyForSigning,
  signChallenge,
} from "../client";

let rsaPair: CryptoKeyPair;
let ecdhPair: CryptoKeyPair;
let pubJwk: JsonWebKey;
let fingerprint: string;

beforeAll(async () => {
  rsaPair = await generateRsaKeyPair();
  ecdhPair = await generateEcdhKeyPair();
  pubJwk = await exportPublicKeyJwk(rsaPair.publicKey);
  fingerprint = await publicKeyFingerprint(pubJwk);
});

// ===== Encoding utilities =====
describe("base64ToBytes / bytesToBase64", () => {
  it("round-trips arbitrary bytes", () => {
    const input = new Uint8Array([0, 1, 2, 3, 255, 128, 64, 32]);
    const b64 = bytesToBase64(input);
    const out = base64ToBytes(b64);
    expect(Array.from(out)).toEqual(Array.from(input));
  });
});

describe("isValidBase64", () => {
  it("accepts valid base64", () => {
    expect(isValidBase64("AAAA")).toBe(true);
    expect(isValidBase64("////")).toBe(true);
    expect(isValidBase64("aGVsbG8=")).toBe(true);
  });

  it("rejects non-base64 strings", () => {
    expect(isValidBase64("not base64!")).toBe(false);
    expect(isValidBase64("")).toBe(false);
    expect(isValidBase64(null)).toBe(false);
    expect(isValidBase64(123)).toBe(false);
  });
});

describe("validateKdfIterations", () => {
  it("accepts values in the valid range", () => {
    expect(validateKdfIterations(310_000)).toBe(true);
    expect(validateKdfIterations(600_000)).toBe(true);
    expect(validateKdfIterations(1_000_000)).toBe(true);
  });

  it("rejects values outside the range", () => {
    expect(validateKdfIterations(0)).toBe(false);
    expect(validateKdfIterations(1)).toBe(false);
    expect(validateKdfIterations(309_999)).toBe(false);
    expect(validateKdfIterations(1_000_001)).toBe(false);
  });

  it("rejects non-number values", () => {
    expect(validateKdfIterations("600000")).toBe(false);
    expect(validateKdfIterations(null)).toBe(false);
    expect(validateKdfIterations(undefined)).toBe(false);
  });
});

describe("validateBase64Blob", () => {
  it("accepts valid base64 within size limits", () => {
    expect(validateBase64Blob("AAAA", 1, 1000)).toBe(true);
    expect(validateBase64Blob("AAAA", 1, 1000)).toBe(true);
  });

  it("rejects oversized blobs", () => {
    const big = "A".repeat(100_000);
    expect(validateBase64Blob(big, 1, 1000)).toBe(false);
  });

  it("rejects undersized blobs", () => {
    expect(validateBase64Blob("AA", 100, 1000)).toBe(false);
  });

  it("rejects invalid base64", () => {
    expect(validateBase64Blob("not base64!", 1, 1000)).toBe(false);
  });
});

// ===== JWK canonicalization =====
describe("canonicalJwkString", () => {
  it("produces the same string regardless of key order", () => {
    const a = canonicalJwkString({ kty: "RSA", n: "abc", e: "AQAB" });
    const b = canonicalJwkString({ e: "AQAB", kty: "RSA", n: "abc" });
    expect(a).toBe(b);
  });
});

describe("publicKeyFingerprint", () => {
  it("produces a 64-char hex SHA-256", async () => {
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces the same fingerprint for the same JWK", async () => {
    const fp2 = await publicKeyFingerprint(pubJwk);
    expect(fp2).toBe(fingerprint);
  });
});

// ===== PoP verification =====
describe("verifyPopSignature", () => {
  it("verifies a signature produced by signPop", async () => {
    const email = "user@example.com";
    const salt = bufToBase64(randomBytes(16));
    const signature = await signPop(rsaPair.privateKey, email, fingerprint, salt);
    const ok = await verifyPopSignature({
      publicKeyJwk: pubJwk,
      signatureB64: signature,
      email,
      fingerprintHex: fingerprint,
      kdfSaltB64: salt,
    });
    expect(ok).toBe(true);
  });

  it("rejects a signature with wrong email", async () => {
    const signature = await signPop(
      rsaPair.privateKey,
      "real@example.com",
      fingerprint,
      bufToBase64(randomBytes(16))
    );
    const ok = await verifyPopSignature({
      publicKeyJwk: pubJwk,
      signatureB64: signature,
      email: "attacker@example.com",
      fingerprintHex: fingerprint,
      kdfSaltB64: bufToBase64(randomBytes(16)),
    });
    expect(ok).toBe(false);
  });
});

// ===== Decoy login response =====
describe("generateDecoyLoginResponse", () => {
  it("returns a deterministic response for the same email", () => {
    const a = generateDecoyLoginResponse("nonexistent@example.com");
    const b = generateDecoyLoginResponse("nonexistent@example.com");
    expect(a).toEqual(b);
  });

  it("returns different responses for different emails", () => {
    const a = generateDecoyLoginResponse("alice@example.com");
    const b = generateDecoyLoginResponse("bob@example.com");
    expect(a).not.toEqual(b);
  });

  it("returns fields that look like a real login response", () => {
    const r = generateDecoyLoginResponse("user@example.com");
    expect(r).toHaveProperty("kdfSalt");
    expect(r).toHaveProperty("kdfIterations");
    expect(r).toHaveProperty("publicKeyJwk");
    expect(r).toHaveProperty("encryptedPrivateKeyJwk");
    expect(r).toHaveProperty("privateKeyIv");
  });
});

// ===== ECDSA challenge verification =====
describe("verifyChallenge (ECDSA P-256)", () => {
  it("verifies a signature produced by signChallenge", async () => {
    const pubJwk = await exportEcdhPublicKeyJwk(ecdhPair.publicKey);
    // Both signChallenge and verifyChallenge work with base64-encoded
    // challenge bytes.
    const challengeB64 = bufToBase64(randomBytes(32));
    const privForSign = await importEcdhPrivateKeyForSigning(
      await (await import("../client")).exportPrivateKeyJwk(ecdhPair.privateKey)
    );
    const signature = await signChallenge(privForSign, challengeB64);

    const ok = await verifyChallenge({
      publicKeyJwk: pubJwk,
      challengeB64,
      signatureB64: signature,
    });
    expect(ok).toBe(true);
  });

  it("rejects a signature for a different challenge", async () => {
    const pubJwk = await exportEcdhPublicKeyJwk(ecdhPair.publicKey);
    const privForSign = await importEcdhPrivateKeyForSigning(
      await (await import("../client")).exportPrivateKeyJwk(ecdhPair.privateKey)
    );
    const realChallenge = bufToBase64(randomBytes(32));
    const signature = await signChallenge(privForSign, realChallenge);

    const differentChallenge = bufToBase64(randomBytes(32));
    const ok = await verifyChallenge({
      publicKeyJwk: pubJwk,
      challengeB64: differentChallenge,
      signatureB64: signature,
    });
    expect(ok).toBe(false);
  });
});

// ===== buildPopMessage =====
describe("buildPopMessage", () => {
  it("produces deterministic bytes for the same input", () => {
    const a = buildPopMessage("user@example.com", "fp", "salt");
    const b = buildPopMessage("user@example.com", "fp", "salt");
    expect(Array.from(a)).toEqual(Array.from(b));
  });
});
